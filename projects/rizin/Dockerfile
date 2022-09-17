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

# Set author of this docker container.
LABEL maintainer="Theodor Arsenij Larionov"

# Install dependencies for build and analysis.
RUN apt-get update && \
    apt-get -y install autoconf automake libtool ninja-build

ENV PATH="${PATH}:/root/.local/bin"

# Install meson
RUN pip3 install --user meson==0.63.0

# Clone target and corpus from github.
RUN mkdir rizin-fuzzing && cd rizin-fuzzing && git clone https://github.com/rizinorg/rizin

WORKDIR /rizin-fuzzing/rizin

# Fix commit. It could be updated later.
RUN git checkout 31148d57ae7131ed2952a45e018dfd11e9c43e81

# Copy patch file that implements fuzzing logic.
COPY build.sh ./
COPY sydr-support-fuzzing.diff ./
COPY rz-fuzz /rizin-fuzzing/rizin/binrz/rz-fuzz

# Build fuzz targets.
RUN ./build.sh

WORKDIR ..

# Create corpus
RUN git clone https://github.com/m4drat/rizin-fuzz-corpus && mv ./rizin-fuzz-corpus/corpus-min /rizin-fuzzing/corpus && rm -rf ./rizin-fuzz-corpus

WORKDIR /fuzz
