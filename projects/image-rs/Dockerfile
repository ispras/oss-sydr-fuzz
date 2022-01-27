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

MAINTAINER Andrey Fedotov
RUN apt-get update && \
    apt-get -y install curl

# Install nightly
RUN rustup install nightly

# Install cargo-fuzz
RUN cargo install cargo-fuzz

# Clone target from GitHub.
RUN git clone https://github.com/image-rs/image

WORKDIR /image

# Checkout specified commit. It could be updated later.
RUN git checkout 69e686ac5d4b0a4aadecf9c689e58519b96cd75d

# Copy build script.
COPY build.sh /

COPY sydr_script_*.rs fuzz/fuzzers/

COPY Cargo.toml fuzz

# Build fuzz targets.
RUN ../build.sh

#Update libfuzzer.
RUN  scrpit=$(find /root/.cargo/registry/src/ -name update-libfuzzer.sh) && $scrpit 3c7960cba19ed926b8e86b4c619e81c0f7da4d15

RUN ../build.sh
