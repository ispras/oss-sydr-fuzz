# Copyright 2021 ISP RAS
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
#RUN apt-get update && apt-get install -y make autoconf automake libtool curl tcl zlib1g-dev

# Clone target from GitHub.
RUN git clone https://github.com/tfussell/xlnt

WORKDIR xlnt

# Checkout specified commit. It could be updated later.
RUN git checkout d88c901faa539f9272a81ba0bab72def70ca18d7 && git submodule update --init --recursive

# Copy build script and targets.
COPY load_fuzzer.cc load_sydr.cc build.sh ./


# Build fuzz targets.
RUN ./build.sh

WORKDIR ..
# Prepare seed corpus.
RUN mkdir /corpus && find /xlnt -name "*.xlsx" | xargs -I {} cp {} /corpus
