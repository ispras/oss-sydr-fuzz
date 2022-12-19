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

# Clone target from GitHub.
RUN git clone https://github.com/serde-rs/json.git

WORKDIR /json

# Checkout specified commit. It could be updated later.
RUN git checkout 94019a31c6036dc4ebb9afc44a214f950caf0d1f

# Copy build script.
COPY build_fuzz.sh build_sydr.sh /

# Build fuzz targets.
RUN ../build_fuzz.sh

COPY sydr_*.rs fuzz/fuzz_targets/

COPY build-config/Cargo.toml fuzz

WORKDIR fuzz

# Build sydr targets.
RUN /build_sydr.sh

COPY json.dict /

WORKDIR /
