# Copyright 2020 Google Inc.
# Modifications copyright (C) 2024 ISP RAS
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
FROM sydr/ubuntu20.04-sydr-fuzz

# Install build dependencies.
RUN apt-get install -y build-essential libssl-dev
RUN wget https://github.com/Kitware/CMake/releases/download/v3.30.1/cmake-3.30.1.tar.gz && \
    tar xf cmake-3.30.1.tar.gz && \
    cd cmake-3.30.1 && \
    ./configure && \
    make

RUN apt-get update && apt-get install -y libpcre3-dev zlib1g-dev mercurial ninja-build liblzma-dev libz-dev binutils libtool

RUN git clone --depth 1 https://github.com/google/libprotobuf-mutator.git
RUN git clone --depth 1 https://github.com/google/fuzzer-test-suite
RUN (mkdir LPM && cd LPM && \
    cmake ../libprotobuf-mutator -GNinja -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON \
        -DLIB_PROTO_MUTATOR_TESTING=OFF -DCMAKE_BUILD_TYPE=Release && ninja)

# Clone target from GitHub. Checkout specified commit. It could be updated later.
RUN hg clone http://hg.nginx.org/nginx/ -u d1b8568f3042

# Copy build script and additional files for Sydr build.
COPY build.sh add_sydr.diff make_sydr /

# Build fuzz targets.
WORKDIR /nginx
RUN /build.sh

WORKDIR /
