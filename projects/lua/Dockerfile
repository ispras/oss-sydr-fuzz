# Copyright 2023 Sergey Bronnikov
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

MAINTAINER Sergey Bronnikov

# Install build dependencies.
RUN apt-get update && apt-get install -y \
	build-essential make coreutils sed \
	autoconf automake libtool zlib1g-dev \
	libreadline-dev libncurses5-dev libssl-dev \
	libunwind-dev luajit wget curl

# Clone target from GitHub.
RUN git clone https://github.com/ligurio/lua-c-api-tests testdir

WORKDIR testdir

# Checkout specified commit. It could be updated later.
RUN git checkout 017105bb03982f558e5111748bdfd44759699a79

# Clone corpus from GitHub.
RUN git clone --depth 1 https://github.com/ligurio/lua-c-api-corpus corpus

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh testdir/

# Build fuzz targets.
RUN testdir/build.sh

WORKDIR /
