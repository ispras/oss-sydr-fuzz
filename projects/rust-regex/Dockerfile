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
FROM sweetvishnya/ubuntu20.04-sydr-fuzz

MAINTAINER Andrey Fedotov
RUN apt-get update && \
    apt-get -y install curl

# Install nightly
RUN rustup install nightly

# Install cargo-fuzz
RUN cargo install cargo-fuzz

# Clone target from GitHub.
RUN git clone https://github.com/rust-lang/regex regex

WORKDIR /regex

# Checkout specified commit. It could be updated later.
RUN git checkout 159a63c85eb77ec321301bc4c4ebfb90343edc2b

# Copy build script.
COPY build.sh /

COPY sydr_*.rs fuzz/fuzz_targets/

COPY build-config/Cargo.toml fuzz

# Build fuzz targets.
RUN ../build.sh

COPY regexp.dict /
