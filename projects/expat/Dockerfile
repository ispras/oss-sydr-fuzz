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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

MAINTAINER Alexey Vishnyakov

# Install build dependencies.
RUN apt-get update && apt-get install -y make autoconf automake libtool docbook2x curl

# Clone target from GitHub.
RUN git clone https://github.com/libexpat/libexpat expat

WORKDIR expat

# Checkout specified commit. It could be updated later.
RUN git checkout 6a36e138f343192d256a0eace730c94170a8141b

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh main.c afl.cc *.dict ./

# Build fuzz targets.
RUN ./build.sh

WORKDIR /

COPY corpus.zip /
RUN unzip /corpus.zip
RUN rm -rf /corpus/empty.xml
