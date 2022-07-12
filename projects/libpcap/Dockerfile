# Copyright 2020 Google Inc.
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

MAINTAINER Ivan Kapranov

RUN apt update && \
    apt install gettext flex bison \
    libtool autoconf automake \ 
    pkg-config -y

RUN git clone https://github.com/fumfel/pcap-fuzzing-corpora.git && \
    mv pcap-fuzzing-corpora corpus

RUN git clone https://github.com/the-tcpdump-group/libpcap.git

WORKDIR /libpcap

COPY load_sydr.c build.sh ./

RUN bash build.sh
