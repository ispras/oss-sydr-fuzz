# Copyright 2017 Google Inc.
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

FROM sydr/ubuntu20.04-sydr-fuzz

RUN git clone https://github.com/uclouvain/openjpeg openjpeg && \
    cd openjpeg && git checkout 6af39314bdb43cb9c7adcdbc7aa9381af42b52ba
RUN git clone https://github.com/uclouvain/openjpeg-data data && \
    cd data && git checkout f9991d5fa9a4a08fc9c29bae6405d6c67cf2b8eb

WORKDIR /

COPY build.sh /

RUN CONFIG="libfuzzer" /build.sh
RUN CONFIG="afl" /build.sh
RUN CONFIG="sydr" /build.sh
RUN CONFIG="coverage" /build.sh
