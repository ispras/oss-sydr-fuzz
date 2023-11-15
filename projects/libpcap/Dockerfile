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

RUN apt-get update && apt-get install -y make cmake flex bison

RUN git clone https://github.com/the-tcpdump-group/libpcap.git libpcap

RUN git clone --depth=1 https://github.com/the-tcpdump-group/tcpdump.git tcpdump

RUN mkdir corpus && mv tcpdump/tests/*.pcap corpus/

WORKDIR libpcap

RUN git checkout 8b8809e3782cfdf7400d966e36bf6249ea106185

COPY build.sh load_sydr_filter.c load_sydr_pcap.c ./

RUN ./build.sh

WORKDIR /
