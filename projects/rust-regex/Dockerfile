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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

MAINTAINER Andrey Fedotov

RUN apt-get update && \
    apt-get -y install curl

# Clone target from GitHub.
RUN git clone https://github.com/rust-lang/regex regex

WORKDIR /regex

# Checkout specified commit. It could be updated later.
RUN git checkout 159a63c85eb77ec321301bc4c4ebfb90343edc2b

# Copy build script.
COPY build_cov.sh build_fuzz.sh build_sydr.sh /

# Build fuzz targets.
RUN ../build_fuzz.sh

COPY sydr_*.rs fuzz/fuzz_targets/

COPY build-config/Cargo.toml fuzz

WORKDIR fuzz

# Build sydr targets.
RUN /build_sydr.sh

# Build cov targets.
RUN cargo clean && /build_cov.sh

COPY regexp.dict /

WORKDIR /

ENV PATH=/root/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/:$PATH
