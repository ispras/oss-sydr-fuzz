# Copyright 2018 Google Inc.
# Modifications copyright (C) 2023 ISP RAS
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

RUN apt-get update && apt-get install -y make autoconf automake libtool bison flex rsync lynx

ADD https://www.bitkeeper.org/downloads/7.3.3/bk-7.3.3-x86_64-glibc213-linux.bin bk-7.3.3-x86_64-glibc213-linux.bin

RUN chmod +x bk-7.3.3-x86_64-glibc213-linux.bin
RUN ./bk-7.3.3-x86_64-glibc213-linux.bin /usr/local/bitkeeper
RUN ln -s /usr/local/bitkeeper/bk /usr/local/bin/bk

WORKDIR /src

RUN bk clone -r1.3714 http://bk.ntp.org/ntp-dev

COPY build.sh patch.diff ./

RUN chmod +x build.sh
RUN ./build.sh

WORKDIR /

RUN mkdir /corpus && echo 1 > /corpus/1
