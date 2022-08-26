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
RUN git checkout c24aecb954b0c9ae96ebdacd023140e323de2d75

# Copy build script.
COPY build.sh /

COPY sydr_script_*.rs fuzz/fuzzers/

COPY build-config/Cargo.toml fuzz

# Build fuzz targets.
RUN ../build.sh

#Update libfuzzer.
RUN  scrpit=$(find /root/.cargo/registry/src/ -name update-libfuzzer.sh) && $scrpit 3c7960cba19ed926b8e86b4c619e81c0f7da4d15

RUN ../build.sh

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
