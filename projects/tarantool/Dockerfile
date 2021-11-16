# Copyright 2021 Google LLC
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

MAINTAINER Alexey Vishnyakov

# Install build dependencies.
RUN apt-get update && apt-get install -y \
	build-essential cmake make coreutils sed \
	autoconf automake libtool zlib1g-dev \
	libreadline-dev libncurses5-dev libssl-dev \
	libunwind-dev libicu-dev luajit

# Clone target from GitHub.
RUN git clone https://github.com/tarantool/tarantool

WORKDIR tarantool

# Checkout specified commit. It could be updated later.
RUN git checkout 03bdb5fff9db1dd4460110ad38da4d4a21d2fe81

RUN git submodule update --init --recursive

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh CMakeLists.txt disable_logging.diff main.c *_fuzzer.c test/fuzz/

# Build fuzz targets.
RUN test/fuzz/build.sh

WORKDIR /
