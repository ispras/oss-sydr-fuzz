# Copyright 2017 Google Inc.
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

RUN apt-get update -y && apt-get install -y autoconf automake libtool curl make g++ unzip wget git \
    binutils liblzma-dev libz-dev python-all ninja-build subversion \
    pkg-config

RUN git clone https://github.com/llvm/llvm-project.git && \
    cd llvm-project && git checkout 499d41cef2e7bbb65804f6a815b9fa8b27efce0f

COPY build.sh /

RUN CONFIG="libfuzzer" /build.sh
#RUN CONFIG="afl" /build.sh
#RUN CONFIG="sydr" /build.sh
#RUN CONFIG="coverage" /build.sh