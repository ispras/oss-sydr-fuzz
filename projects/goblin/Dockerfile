# Copyright 2022 ISP RAS
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

MAINTAINER Andrey Fedotov
RUN apt-get update && \
    apt-get -y install curl

# Copy build script.
COPY build_cov.sh build_fuzz.sh build_sydr.sh /

# Clone target from GitHub.
RUN git clone https://github.com/m4b/goblin.git

WORKDIR /goblin

# Checkout specified commit. It could be updated later.
RUN git checkout d035559b991e631eae7aa91d89cde5e5e03e9cc6

# Build fuzz targets.
RUN ../build_fuzz.sh

RUN rm -rf fuzz/target

COPY build-config/Cargo.toml fuzz/

COPY sydr_*.rs fuzz/fuzz_targets/

WORKDIR fuzz

# Build sydr targets.
RUN /build_sydr.sh

# Build cov targets.
RUN cargo clean && /build_cov.sh

WORKDIR /

#Create corpus
RUN git clone https://github.com/JonathanSalwan/binary-samples /corpus && \
rm -rf /corpus/anti-disassembler && rm /corpus/MIT_LICENSE && rm /corpus/README.md

ENV PATH=/root/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/:$PATH
