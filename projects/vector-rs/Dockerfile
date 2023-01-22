# Copyright 2022 ISP RAS
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

RUN apt-get update && \
    apt-get -y install curl

# Copy build script.
COPY build.sh /

# Clone target from GitHub.
RUN git clone https://github.com/vectordotdev/vector --branch v0.25.0

# Copy harness
COPY fuzzing /vector/lib/vrl/stdlib/fuzzing
RUN mkdir /fuzz_vector
COPY fuzz_update_patches /fuzz_vector/fuzz_update_patches

#Apply patches
RUN patch -p0 < /fuzz_vector/fuzz_update_patches/parse_xml.patch && \
patch -p0 < /fuzz_vector/fuzz_update_patches/parse_json.patch && \
patch -p0 < /fuzz_vector/fuzz_update_patches/parse_csv.patch && \
patch -p0 < /fuzz_vector/fuzz_update_patches/parse_klog.patch && \
patch -p0 < /fuzz_vector/fuzz_update_patches/parse_aws.patch && \
patch -p0 < /fuzz_vector/fuzz_update_patches/stdlib.patch && \
sed -i 's/0.4.19/=0.4.22/' /vector/lib/value/Cargo.toml
# Build targets.
WORKDIR vector

RUN rm rust-toolchain.toml


RUN /build.sh

#Copy dictionaries
COPY dict /dict

# Rust toolchain first
ENV PATH=/root/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/:$PATH
