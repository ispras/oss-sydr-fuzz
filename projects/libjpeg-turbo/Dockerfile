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

MAINTAINER Andrey Fedotov

# Install build dependencies.
RUN apt-get update && apt-get install -y make yasm cmake

# Clone target from GitHub.
RUN git clone https://github.com/libjpeg-turbo/libjpeg-turbo

WORKDIR libjpeg-turbo

# Checkout specified commit. It could be updated later.
RUN git checkout df3c3dcb9b0b24d78f9e58e28c8b509a49967ba8

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh compress_sydr.cc decompress_sydr.cc transform_sydr.cc ./fuzz/

# Build fuzz targets.
RUN ./fuzz/build.sh

WORKDIR /

# Prepare seed corpus.
RUN git clone --depth 1 https://github.com/libjpeg-turbo/seed-corpora
RUN mkdir /corpus_decompress && cd seed-corpora && \
    find afl-testcases/jpeg* bugs/decompress* -type f | xargs -I {} cp {} /corpus_decompress && \
    cp /libjpeg-turbo/testimages/*.jpg /corpus_decompress
RUN mkdir /corpus_compress && cd seed-corpora && \
    find afl-testcases/bmp afl-testcases/gif* bugs/compress* -type f | xargs -I {} cp {} /corpus_compress && \
    cp /libjpeg-turbo/testimages/*.bmp /libjpeg-turbo/testimages/*.ppm /corpus_compress
RUN rm -rf seed-corpora
