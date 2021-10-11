# Copyright 2016 Google Inc.
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

MAINTAINER Alexey Vishnyakov

# Install build dependencies.
RUN apt-get update && apt-get install -y make autoconf automake libtool curl tcl zlib1g-dev

# Clone target from GitHub.
RUN git clone https://github.com/sqlite/sqlite.git sqlite3-src

WORKDIR sqlite3-src

# Checkout specified commit. It could be updated later.
RUN git checkout c06836c3b1461afcadfb68b20cbf41f0c41d3105

# Copy build script.
COPY build.sh .

# Copy source code for Sydr fuzz target.
COPY sydrfuzz.c test

# Build fuzz targets.
RUN ./build.sh

WORKDIR ..
# Prepare seed corpus.
RUN mkdir /corpus && find /sqlite3-src -name "*.test" | xargs -I {} cp {} /corpus
