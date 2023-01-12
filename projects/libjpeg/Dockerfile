# Copyright 2016 Google Inc.
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

FROM sydr/ubuntu20.04-sydr-fuzz

MAINTAINER Georgy Savidov

# Install build dependencies.
RUN apt-get update && apt-get install -y make yasm wget

COPY build.sh jcompress_sydr.cc jcompress_fuzzer.cc \
     jdecompress_sydr.cc jdecompress_fuzzer.cc jpeg-9e.patch ./fuzz/

RUN wget http://www.ijg.org/files/jpegsrc.v9e.tar.gz && \
    tar -xnf jpegsrc.v9e.tar.gz && \
    patch -s -p0 < /fuzz/jpeg-9e.patch

WORKDIR jpeg-9e

RUN /fuzz/build.sh

WORKDIR /

RUN git clone --depth 1 https://github.com/libjpeg-turbo/seed-corpora
RUN mkdir /corpus_decompress && cd seed-corpora && \
    find afl-testcases/jpeg/full/images/id\:002* bugs/decompress* -type f | xargs -I {} cp {} /corpus_decompress && \
    cp /jpeg-9e/*.jpg /corpus_decompress
RUN mkdir /corpus_compress && cd seed-corpora && \
    find afl-testcases/bmp afl-testcases/gif* afl-testcases/targa bugs/compress* -type f | xargs -I {} cp {} /corpus_compress && \
    cp /jpeg-9e/*.bmp /jpeg-9e/*.ppm /corpus_compress
RUN rm /corpus_decompress/101376530-fde56180-38b0-11eb-938d-734119a5b5ba.jpg \
    /corpus_decompress/b64876977.poc \
    /corpus_decompress/125976848-341500ce-1b67-4dfc-8e6f-313ce9fedcef.jpg \
    /corpus_decompress/overflow*
RUN rm -rf seed-corpora
