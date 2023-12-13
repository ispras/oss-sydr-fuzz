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

FROM sydr/ubuntu20.04-sydr-fuzz

MAINTAINER Andrey Fedotov

# Install build dependencies.
RUN apt-get update && apt-get install -y make autoconf automake libtool

# Clone target from GitHub.
RUN git clone https://github.com/mm2/Little-CMS.git lcms

WORKDIR lcms

# Checkout specified commit. It could be updated later.
RUN git checkout bce906a970683fdb692d4174c067b977c8ab6aa7

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh cms_link.c cmsIT8_load.c cms_transform.c cms_overwrite_transform.c ./
COPY afl.cc /

# Build fuzz targets.
RUN ./build.sh

WORKDIR ..
# Prepare seed corpus.
RUN mkdir /corpus && find . -name "*.icc" | xargs -I {} cp {} /corpus/
RUN cp -r /corpus /link_corpus
RUN for file in /link_corpus/*; do sed -i '1s/^/\x01\x20\x08/' $file; done
