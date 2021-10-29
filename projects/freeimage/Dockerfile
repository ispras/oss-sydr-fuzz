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

FROM xcoldhandsx/dev-test

# Set author of this docker container.
MAINTAINER Andrey Fedotov

# Install dependencies.
RUN apt-get update && apt-get install -y subversion  autoconf automake libtool wget

# Checkout FreeImage.
RUN svn checkout https://svn.code.sf.net/p/freeimage/svn/ freeimage-svn

WORKDIR /freeimage-svn/FreeImage/trunk/

# Copy targets and build script.
COPY build.sh ./
COPY load_from_memory_sydr.cc load_from_memory_fuzzer.cc /

# Run build script.
RUN ./build.sh

WORKDIR /
