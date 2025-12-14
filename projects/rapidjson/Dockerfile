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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

# Clone target from github.
RUN git clone https://github.com/Tencent/rapidjson.git /rapidjson

WORKDIR /rapidjson

# Fix commit. It could be updated.
RUN git checkout 24b5e7a8b27f42fa16b96fc70aade9106cf7102f 

# Copy target for sydr
COPY fuzzer.cpp build.sh .

#  Build targets.
RUN ./build.sh

WORKDIR /

# Prepare corpus
RUN mkdir /corpus
RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git && \
    cp /go-fuzz-corpus/json/corpus/* /corpus/ && \
    rm -rf /go-fuzz-corpus
RUN find /rapidjson -name "*.json" | xargs -I {} cp {} /corpus


