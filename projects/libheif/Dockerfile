# Copyright 2019 Google Inc.
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
ARG CMAKE_VERSION=3.27.6

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    libbrotli-dev \
    libtool \
    make \
    mercurial \
    pkg-config \
    yasm \
    zlib1g-dev

WORKDIR /opt
RUN wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz && \
    tar -xzf cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz && \
    mv cmake-${CMAKE_VERSION}-linux-x86_64 /opt/cmake && \
    ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake && \
    rm cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz

WORKDIR /src
    
RUN git clone https://github.com/strukturag/libde265.git libde265 && \
    cd libde265 && \
    git checkout 6783111

RUN git clone \
    https://bitbucket.org/multicoreware/x265_git/src/stable/ \
    x265

RUN git clone \
    --depth 1 \
    --branch master \
    https://aomedia.googlesource.com/aom \
    aom


RUN git clone https://github.com/strukturag/libheif.git libheif && \
    cd libheif && \
    git checkout 83617f6e49e247f274b6d8826548ff6a63f56e5a

COPY build.sh build.sh    
RUN chmod +x build.sh && ./build.sh

