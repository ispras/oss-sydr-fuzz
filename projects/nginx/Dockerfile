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
RUN apt-get update && apt-get install -y libpcre3-dev zlib1g-dev mercurial ninja-build liblzma-dev \
    libz-dev binutils libtool build-essential libssl-dev
RUN wget https://github.com/Kitware/CMake/releases/download/v3.30.1/cmake-3.30.1.tar.gz && \
    tar xf cmake-3.30.1.tar.gz && \
    cd cmake-3.30.1 && \
    ./configure && \
    make

RUN git clone --depth 1 https://github.com/google/libprotobuf-mutator.git
RUN git clone --depth 1 https://github.com/google/fuzzer-test-suite

# Clone target from GitHub. Checkout specified commit. It could be updated later.
RUN hg clone http://hg.nginx.org/nginx/ -u d1b8568f3042

# Save fuzz target and additional files for libFuzzer and AFL++ builds
RUN mkdir /nginx/src/fuzz
ADD https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/fuzz/http_request_fuzzer.cc /nginx/src/fuzz/http_request_fuzzer.cc
ADD https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/fuzz/http_request_proto.proto /nginx/src/fuzz/http_request_proto.proto
ADD https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/fuzz/wrappers.c /nginx/src/fuzz/wrappers.c

ADD https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/add_fuzzers.diff /add_fuzzers.diff
ADD https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/make_fuzzers /make_fuzzers
ADD https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/fuzz/http_request_fuzzer.dict /http_request_fuzzer.dict

# Prepare seed corpora
RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git /go-fuzz-corpus && \
    cp -r /go-fuzz-corpus/http2/corpus /corpus && \
    cp /go-fuzz-corpus/httpreq/corpus/* /corpus && \
    rm /corpus/da39a3ee5e6b4b0d3255bfef95601890afd80709-2 && \
    rm /corpus/da39a3ee5e6b4b0d3255bfef95601890afd80709-1 && \
    rm -rf /go-fuzz-corpus

# Copy build script and additional files for Sydr build.
COPY build.sh add_sydr.diff make_sydr /

# Build fuzz targets.
RUN /build.sh
