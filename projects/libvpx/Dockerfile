# Copyright 2018 Google Inc.
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

RUN apt-get update && apt-get install -y yasm

RUN git clone https://github.com/webmproject/libvpx.git && cd libvpx && git checkout 58a854fb271f99a15f3d2687587f74a6d12c8512
ADD https://storage.googleapis.com/downloads.webmproject.org/test_data/fuzzer/vpx_fuzzer_seed_corpus.zip /
RUN unzip vpx_fuzzer_seed_corpus.zip && mkdir corpus && find / -name "*.ivf" -exec cp {} corpus \;

COPY build.sh vpx_dec_fuzzer.dict /
COPY main.cc /libvpx/
RUN ./build.sh
