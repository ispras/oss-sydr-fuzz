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

# Set author of this docker container.
MAINTAINER Andrey Fedotov

# Install dependencies for build and analysis.
RUN apt-get update && \
    apt-get -y install autoconf automake libtool

# Clone target from github.
RUN git clone https://github.com/google/re2

WORKDIR re2

# Fix commit. It could be updated later.
RUN git checkout 0dade9ff39bb6276f18dd6d4bc12d3c20479ee24

# Copy modified build scripts for fuzz targets.
COPY ./build.sh ./

# Copy source code for sydr fuzz target.
COPY re2_sydr.cc ./re2/fuzzing/

# Build fuzz targets.
RUN ./build.sh

WORKDIR ..
