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

# Install build dependencies.
RUN apt-get update && apt-get install -y  libssl-dev

# Clone target from GitHub.
RUN git clone  https://github.com/pocoproject/poco
WORKDIR /poco

# Checkout specified commit. It could be updated later.
RUN git checkout 94832726810a3116ce8c9887c17675716dbb6243

# Copy build script and targets.
COPY build.sh \
     json_parse_fuzzer.cc \
     json_parse_sydr.cc \
     xml_parse_fuzzer.cc \
     xml_parse_sydr.cc \
     /

# Build fuzz targets.
RUN ../build.sh

WORKDIR /

# Prepare json seed corpus.
RUN mkdir corpus_json && find  ./poco -name "*.json" -exec cp {} /corpus_json \;

# Prepare xml seed corpus.
RUN mkdir corpus_xml && find  ./poco -name "*.xml" -exec cp {} /corpus_xml \;
