# Copyright 2016 Google Inc.
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

MAINTAINER Daniil Kuts

# Install build dependencies.
RUN apt-get update && apt-get install -y make

# Clone target from GitHub.
RUN git clone https://github.com/openssl/openssl.git

WORKDIR openssl

# Checkout specified commit. It could be updated later.
RUN git checkout ff3e4508bde0d7f7ab211ca9f027bef820ba1d70

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh ./
COPY targets/*_sydr.c ./fuzz/

# Build fuzz targets.
RUN ./build.sh

WORKDIR /
