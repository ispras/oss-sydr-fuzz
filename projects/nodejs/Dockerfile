# Copyright 2017 Google Inc.
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

RUN apt-get update && apt-get install -y make \
        python3

RUN git clone https://github.com/nodejs/node /node_afl

WORKDIR /node_afl

RUN git checkout 86088ab78e8c3739f60627ddf21f65da7796450e

WORKDIR /

RUN cp -r /node_afl /node_cov
RUN cp -r /node_afl /node_sydr
RUN cp -r /node_afl /node_libfuzzer

COPY v8_compile.cc /node_afl/test/fuzzers
COPY v8_compile_sydr.cc /node_sydr/test/fuzzers/v8_compile.cc
COPY v8_compile_sydr.cc /node_cov/test/fuzzers/v8_compile.cc

COPY *.patch /
RUN patch /node_libfuzzer/node.gyp /libfuzzer.patch && \
    patch /node_afl/node.gyp /afl.patch && \
    patch /node_sydr/node.gyp /sydr.patch && \
    patch /node_cov/node.gyp /cov.patch

COPY js.dict build.sh build_url_corpus.sh /
RUN ./build.sh
RUN ./build_url_corpus.sh

RUN mkdir /corpus && find node_afl -type f -name "*.js" | xargs -I {} cp -r {} /corpus
RUN mkdir /reduced_corpus && cp /corpus/a* /reduced_corpus/ && \
     cp /corpus/b* /reduced_corpus/ &&  cp /corpus/c* /reduced_corpus/ && \
     cp /corpus/p* /reduced_corpus/ &&  cp /corpus/m* /reduced_corpus/ && \
     cp /corpus/s* /reduced_corpus/
