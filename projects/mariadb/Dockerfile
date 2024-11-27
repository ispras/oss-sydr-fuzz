# Copyright 2023 Google LLC
# Modifications copyright (C) 2023 ISP RAS
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

RUN apt-get update && \
    apt-get install -y libncurses5-dev gnutls-dev bison ccache lz4 liblzma-dev

RUN git clone https://github.com/MariaDB/server && cd server && \
    git checkout 94eb819296c99b2f1d1a68a5a12eabe18e2f4874

WORKDIR /

COPY build.sh *.c json.dict /

RUN CONFIG="libfuzzer" /build.sh
RUN CONFIG="afl" /build.sh
RUN CONFIG="sydr" /build.sh
RUN CONFIG="coverage" /build.sh

RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git /go-fuzz-corpus && \
    mkdir /corpus && cp /go-fuzz-corpus/json/corpus/* /corpus && rm -rf /go-fuzz-corpus
RUN for file in /corpus/*; do \
        sed -i '/{/s/^/1/' $file; \
        sed -i '/{/s/^/2/' $file; \
        sed -i '/{/s/^/3/' $file; \
        sed -i '/{/s/^/4/' $file; done
