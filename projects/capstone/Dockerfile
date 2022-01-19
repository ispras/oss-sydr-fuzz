# Copyright 2018 Google Inc.
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
RUN apt-get update && apt-get install -y make cmake python python-setuptools

# Clone target from GitHub.
RUN git clone --branch v4 https://github.com/aquynh/capstone.git capstonev4
RUN git clone --branch next https://github.com/aquynh/capstone.git capstonenext

# Checkout specified commit. It could be updated later.
RUN cd capstonenext && \
    git checkout 06a102f4dcc62d192dbd138d068235fd717375a7 && \
    cd ..

# Copy build script.
COPY build.sh /

# Build fuzz targets.
RUN ./build.sh
