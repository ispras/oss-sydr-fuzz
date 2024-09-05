# Copyright 2017 Google Inc.
# Modifications copyright (C) 2024 ISP RAS
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

# Install build dependencies.
RUN apt-get update && apt-get install -y libz-dev libssl1.1 libssl-dev \
                        libtirpc-dev libedit-dev

# Clone target from GitHub.
RUN git clone https://github.com/openssh/openssh-portable openssh
RUN git clone --depth 1 https://github.com/djmdjm/openssh-fuzz-cases

WORKDIR openssh

# Checkout specified commit. It could be updated later.
RUN git checkout 1ec0a64c5dc57b8a2053a93b5ef0d02ff8598e5c

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY sshd_session_fuzz.cc ssh.patch build.sh fuzzer_temp_file.h ./

# Build fuzz targets.
COPY server_config_fuzz.cc ./regress/misc/fuzz-harness/lsc_fuzz.cc
RUN ./build.sh

WORKDIR /
