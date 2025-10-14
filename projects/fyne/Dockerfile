# Copyright (C) 2025 ISP RAS
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

ARG BASE_IMAGE="sydr/ubuntu22.04-sydr-fuzz"
FROM $BASE_IMAGE

WORKDIR /

RUN apt-get update && apt-get install -y libgl1-mesa-dev pkg-config xorg-dev \
    libxrandr-dev libxi-dev libxcursor-dev libxinerama-dev libgl-dev

RUN git clone https://github.com/fyne-io/fyne.git

WORKDIR /fyne

RUN git checkout 19dcdbdb5f5a9b293a21a29b5235c163345b36d0

RUN go get github.com/dvyukov/go-fuzz/go-fuzz-dep

COPY build.sh ./
COPY fuzz.go ./fuzz/

RUN mkdir cmd/sydr_image_file && \
    mkdir cmd/sydr_image_raster && \
    mkdir cmd/sydr_image_reader && \
    mkdir cmd/sydr_image_uri && \
    mkdir cmd/sydr_resource_uri && \
    mkdir cmd/sydr_text_layout

COPY sydr_image_file.go cmd/sydr_image_file/main.go
COPY sydr_image_raster.go cmd/sydr_image_raster/main.go
COPY sydr_image_reader.go cmd/sydr_image_reader/main.go
COPY sydr_image_uri.go cmd/sydr_image_uri/main.go
COPY sydr_resource_uri.go cmd/sydr_resource_uri/main.go
COPY sydr_text_layout.go cmd/sydr_text_layout/main.go

# Build targets.
RUN ./build.sh

WORKDIR /

# Prepare corpus.
RUN git clone --depth=1 https://github.com/dvyukov/go-fuzz-corpus.git
RUN mkdir /corpus-image /corpus-text
RUN cp go-fuzz-corpus/png/corpus/* /corpus-image
RUN cp go-fuzz-corpus/jpeg/corpus/* /corpus-image
RUN cp go-fuzz-corpus/gif/corpus/* /corpus-image
RUN cp go-fuzz-corpus/asm/corpus/* /corpus-text
RUN cp go-fuzz-corpus/json/corpus/* /corpus-text
