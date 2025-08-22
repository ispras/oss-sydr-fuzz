# Copyright 2019 Google Inc.
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

MAINTAINER Ilya Yegorov (hkctkuy)

# Install build dependencies.
RUN pip3 install hypothesis

# Clone repo corpus and dict.
RUN git clone https://github.com/DaveGamble/cJSON.git cjson

WORKDIR /out/corpus

# Prepare seed corpus.
RUN cp -r /cjson/fuzzing/inputs/* .
RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git /go-fuzz-corpus && \
    cp /go-fuzz-corpus/json/corpus/* . && rm -rf /go-fuzz-corpus

WORKDIR /

# Clone target from GitHub.
RUN git clone https://github.com/ultrajson/ultrajson.git ultrajson

WORKDIR ultrajson

# Checkout specified commit. It could be updated later.
RUN git checkout 18607247be7c8a2d884396888fda3e514c7db612

RUN rustup toolchain uninstall nightly && rustup toolchain install nightly && rustup update

RUN apt install python3.9-venv

COPY \
    hypothesis_structured_fuzzer.py \
    json_differential_fuzzer.py \
    ujson_fuzzer_atheris.py \
    ujson_fuzzer_pyafl.py \
    /

COPY build_*.sh /

ARG BUILD_SCRIPT
RUN /$BUILD_SCRIPT
