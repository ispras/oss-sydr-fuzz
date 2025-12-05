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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

MAINTAINER Andrey Fedotov

RUN git clone https://github.com/golang/image.git
RUN git clone --depth=1 https://github.com/dvyukov/go-fuzz-corpus.git

WORKDIR image

RUN git checkout c574db581976698ac047466629eeeb7b17bb49dd

RUN go get github.com/dvyukov/go-fuzz/go-fuzz-dep

COPY fuzz.go build.sh ./

# Move target and additional libs to main project.
RUN cp -r /usr/local/go/src/image/png . && \
    cp -r /usr/local/go/src/image/jpeg . && \
    cp -r /usr/local/go/src/image/gif . && \
    cp -r /usr/local/go/src/internal/byteorder . && \
    cp -r /usr/local/go/src/image/internal/imageutil .

RUN mkdir cmd/sydr_webp && \
    mkdir cmd/sydr_tiff && \
    mkdir cmd/sydr_png && \
    mkdir cmd/sydr_jpeg && \
    mkdir cmd/sydr_gif

COPY sydr_webp.go cmd/sydr_webp/main.go
COPY sydr_tiff.go cmd/sydr_tiff/main.go
COPY sydr_png.go cmd/sydr_png/main.go
COPY sydr_jpeg.go cmd/sydr_jpeg/main.go
COPY sydr_gif.go cmd/sydr_gif/main.go

RUN ./build.sh

WORKDIR /

COPY *.dict /
