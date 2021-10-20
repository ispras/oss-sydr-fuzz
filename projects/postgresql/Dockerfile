# Copyright 2020 Google Inc.
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
RUN apt-get update && apt-get install -y make libreadline-dev zlib1g-dev bison flex

# Clone target from GitHub.
RUN git clone git://git.postgresql.org/git/postgresql.git

WORKDIR postgresql

# Checkout specified commit. It could be updated later.
RUN git checkout 998d060f3db79c6918cb4a547695be150833f9a4

RUN mkdir bld && mkdir /corpus && mkdir fuzzer && mkdir /out
# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY ./fuzzer fuzzer
COPY build.sh add_fuzzers.diff ./

# Build fuzz targets.
RUN ./build.sh

# Prepare seed corpus.
WORKDIR /corpus
RUN cp -r /postgresql/src/test/regress/sql/* .
WORKDIR /
