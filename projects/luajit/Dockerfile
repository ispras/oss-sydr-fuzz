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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

MAINTAINER Sergey Bronnikov

# Install build dependencies.
RUN apt-get update && apt-get install -y \
	libreadline-dev libunwind-dev

# Clone target from GitHub.
RUN git clone https://github.com/ligurio/lua-c-api-tests testdir

WORKDIR testdir

# Checkout specified commit. It could be updated later.
RUN git checkout f0b2821c0defc86b0755fc0cf96ad9386bfcfe44

# Clone corpus from GitHub.
RUN git clone --depth 1 https://github.com/ligurio/lua-c-api-corpus corpus

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh testdir/

# Build fuzz targets.
RUN testdir/build.sh

WORKDIR /
