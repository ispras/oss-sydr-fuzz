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
FROM sydr/ubuntu20.04-sydr-fuzz

MAINTAINER Andrey Fedotov
RUN apt-get update && \
    apt-get -y install curl

# Clone target from GitHub.
RUN git clone https://github.com/image-rs/image

WORKDIR /image

# Checkout specified commit. It could be updated later.
RUN git checkout b35437696f4ccb39cd5250552f6cfe1734a27bcd

# Copy build script.
COPY build_cov.sh build_fuzz.sh build_sydr.sh /

# Build fuzz targets.
RUN ../build_fuzz.sh

RUN rm -rf fuzz/target

COPY sydr_script_*.rs fuzz/fuzzers/

COPY build-config/Cargo.toml fuzz/

WORKDIR fuzz

# Build sydr targets.
RUN /build_sydr.sh

# Build cov targets.
RUN cargo clean && /build_cov.sh

# Prepare corporas.
RUN mkdir /corpus_bmp && find /image -name '*.bmp' -exec cp {} /corpus_bmp \; && \
    mkdir /corpus_gif && find /image -name '*.gif' -exec cp {} /corpus_gif \; && \
    mkdir /corpus_hdr && find /image -name '*.hdr' -exec cp {} /corpus_hdr \; && \
    mkdir /corpus_ico && find /image -name '*.ico' -exec cp {} /corpus_ico \; && \
    mkdir /corpus_jpg && find /image -name '*.jpg' -exec cp {} /corpus_jpg \; && \
    mkdir /corpus_png && find /image -name '*.png' -exec cp {} /corpus_png \; && \
    mkdir /corpus_pnm && find /image -name '*.pnm' -exec cp {} /corpus_pnm \; && \
    mkdir /corpus_tga && find /image -name '*.tga' -exec cp {} /corpus_tga \; && \
    mkdir /corpus_tiff && find /image -name '*.tiff' -exec cp {} /corpus_tiff \; && \
    mkdir /corpus_webp && find /image -name '*.webp' -exec cp {} /corpus_webp \; && \
    cp -r /image/tests/images/exr /corpus_exr

ENV PATH=/root/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/:$PATH
