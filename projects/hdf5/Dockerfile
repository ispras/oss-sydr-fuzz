# Copyright 2023 Google Inc.
# Modifications copyright (C) 2023 ISP RAS
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

MAINTAINER Kobrin Eli

RUN git clone https://github.com/HDFGroup/hdf5 && cd hdf5 && \
    git checkout 509fe962d42b3f02d356d2668b04712df06daf7f

WORKDIR /hdf5

COPY build.sh *.c corpus.zip /

RUN /build.sh

WORKDIR /

RUN unzip corpus.zip
