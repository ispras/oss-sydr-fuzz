# Copyright 2016 Google Inc.
# Modifications copyright (C) 2022 ISP RAS
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

MAINTAINER Ilya hkctkuy Yegorov

RUN apt-get update && apt-get install -y make autoconf automake libtool zip

RUN git clone  https://github.com/madler/zlib.git

WORKDIR /zlib

RUN git checkout 04f42ceca40f73e2978b50e93806c2a18c1281fc

COPY afl.cc *.c* build.sh \
         ./

RUN ./build.sh
