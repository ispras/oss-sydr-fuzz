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
RUN apt-get update

RUN apt-get install -y make libtool libssl-dev libexpat-dev wget

RUN git clone https://github.com/NLnetLabs/unbound unbound

WORKDIR unbound

# Checkout commit.
RUN git checkout 7749d98a14359200d6d37028f27f07fd823623a1

COPY parse_packet_fuzzer.c .

COPY fuzz_1.c .
COPY fuzz_2.c .
COPY fuzz_3.c .
COPY fuzz_4.c .
COPY main.c .
COPY build.sh ./

RUN ./build.sh

WORKDIR /
RUN wget  --directory-prefix / https://github.com/jsha/unbound/raw/fuzzing-corpora/testdata/parse_packet_fuzzer_seed_corpus.zip && \
unzip parse_packet_fuzzer_seed_corpus.zip && mv testdata corpus_packet && rm parse_packet_fuzzer_seed_corpus.zip
