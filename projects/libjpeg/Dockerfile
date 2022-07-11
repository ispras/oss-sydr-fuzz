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


COPY build.sh jcompress_sydr.cc jcompress_fuzzer.cc jpegsrc.v9e.tar.gz ./fuzz/

RUN tar -xnf ./fuzz/jpegsrc.v9e.tar.gz

COPY rdgif.c /jpeg-9e
COPY rdtarga.c /jpeg-9e

WORKDIR jpeg-9e

RUN /fuzz/build.sh

WORKDIR /

RUN git clone --depth 1 https://github.com/libjpeg-turbo/seed-corpora
RUN mkdir /corpus_compress && cd seed-corpora && \
    find afl-testcases/bmp afl-testcases/gif* bugs/compress* -type f | xargs -I {} cp {} /corpus_compress && \
    cp /jpeg-9e/*.bmp /jpeg-9e/*.ppm /corpus_compress
RUN rm -rf seed-corpora
