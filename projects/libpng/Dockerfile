# Copyright 2016 Google Inc.
# Modifications copyright (C) 2022 ISP RAS
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

MAINTAINER Ilya Yegorov (hkctkuy)

# Install build dependencies.
RUN apt-get update && \
    apt-get install -y make autoconf automake libtool zlib1g-dev

# Clone target from GitHub.

RUN git clone https://github.com/glennrp/libpng.git

WORKDIR /libpng

# Checkout specified commit. It could be updated later.
RUN git checkout a37d4836519517bdce6cb9d956092321eca3e73b

COPY *.c* build.sh \
         ./

RUN ./build.sh
