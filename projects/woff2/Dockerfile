# Copyright 2016 Google Inc.
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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN apt-get update && apt-get install -y libbrotli-dev

RUN git clone --recursive https://github.com/google/woff2 /src/woff2

WORKDIR /src/woff2

RUN git checkout 0f4d304faa1c62994536dc73510305c7357da8d4

COPY build.sh ./

RUN mkdir -p targets
RUN ./build.sh

WORKDIR /
COPY corpus.zip /
RUN unzip corpus.zip && rm corpus.zip
