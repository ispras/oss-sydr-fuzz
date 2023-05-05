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
RUN git checkout 365d59c1f02109b5d22d79a0b2a2cb97961ff262

# Clone corpus from GitHub.
RUN git clone --depth 1 https://github.com/ligurio/lua-c-api-corpus corpus

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh testdir/

# Build fuzz targets.
RUN testdir/build.sh

WORKDIR /

# Developers of PUC Rio Lua team left a comment regarding used ASAN options:
# > The following options help detect "undefined behavior"s that seldom
# > create problems; some are only available in newer gcc versions. To
# > use some of them, we also have to define an environment variable
# > ASAN_OPTIONS="detect_invalid_pointer_pairs=2".
# See https://github.com/lua/lua/blob/e15f1f2bb7a38a3c94519294d031e48508d65006/makefile#L60-L66
# https://github.com/google/sanitizers/wiki/AddressSanitizerFlags

# We comment this, because all of the afl++ fuzz targets are
# failing due to invalid pointer pairs errors.
# ENV ASAN_OPTIONS="detect_invalid_pointer_pairs=2"
