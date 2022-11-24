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

# Set author of this docker container.
MAINTAINER Andrey Fedotov

# Install dependencies.
RUN apt-get update && apt-get install -y subversion  autoconf automake libtool wget

# Checkout FreeImage.
RUN svn checkout -r 1903 https://svn.code.sf.net/p/freeimage/svn/ freeimage-svn

WORKDIR /freeimage-svn/FreeImage/trunk/

# Copy targets and build script.
COPY build.sh ./
COPY *_fuzzer.cc *_sydr.cc \
     corpus_bmp.zip corpus_tiff.zip corpus_jpeg.zip /

# Run build script.
RUN ./build.sh

WORKDIR /

# Prepare corporas

RUN unzip corpus_bmp.zip && unzip corpus_tiff.zip && unzip corpus_jpeg.zip
