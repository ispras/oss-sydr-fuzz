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

FROM sweetvishnya/ubuntu20.04-sydr-fuzz

RUN apt-get update && apt-get install -y binutils-gold \
        gnupg \
        libgcc \
        linux-headers \
        make \
        python

RUN git clone https://github.com/nodejs/node /node_sydr 

WORKDIR /node_sydr

RUN git checkout v16.x

COPY main.c ./
COPY v8_compile.cpp ./fuzz.cpp

WORKDIR /

COPY /node_sydr /node_cov
COPY /node_sydr /node_libfuzzer

RUN ./build.sh

RUN mkdir /corpus && find node -name "*.js" | xargs -I {} cp {} /corpus
