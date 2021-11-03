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

FROM sweetvishnya/ubuntu20.04-sydr-fuzz

MAINTAINER Andrey Fedotov

# Install build dependencies.
RUN apt-get update && apt-get install -y make cmake

# Clone target from GitHub.
RUN git clone https://github.com/PJK/libcbor

WORKDIR libcbor

# Checkout specified commit. It could be updated later.
RUN git checkout aa79fb7ba5e032c50530c689b6f20f2a74cafa97

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh cbor_load_sydr.cc ./oss-fuzz/

# Build fuzz targets.
RUN ./oss-fuzz/build.sh

# Prepare seed corpus.
RUN mkdir /corpus && find . -name "*.cbor" | xargs -I {} cp {} /corpus/

WORKDIR ..
