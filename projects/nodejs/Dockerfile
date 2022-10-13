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

RUN apt-get update && apt-get install -y make \
        python3

RUN git clone https://github.com/nodejs/node /node_afl

WORKDIR /node_afl

RUN git checkout v16.x

COPY v8_compile.cpp v8_compile_sydr.cpp ./

WORKDIR /

RUN cp -r /node_afl /node_cov
RUN cp -r /node_afl /node_sydr

COPY js.dict build.sh /
RUN ./build.sh

RUN mkdir /corpus && find node_afl -type f -name "*.js" | xargs -I {} cp -r {} /corpus