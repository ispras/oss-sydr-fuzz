# Copyright (C) 2023 ISP RAS
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

RUN apt-get update && apt-get install -y flex bison

RUN git clone https://github.com/the-tcpdump-group/libpcap.git libpcap
RUN cd libpcap && git checkout e0be22909d285fa721379542a754df696c314da3

RUN git clone https://github.com/the-tcpdump-group/tcpdump.git tcpdump
RUN cd tcpdump && git checkout 1e63a2f6903de9303931f3135db88932d4e5785a

RUN mkdir corpus && mv tcpdump/tests/*.pcap corpus/

COPY build.sh pretty_print_packet.c main.c /

RUN CONFIG="libfuzzer" /build.sh
RUN CONFIG="afl" /build.sh
RUN CONFIG="sydr" /build.sh
RUN CONFIG="coverage" /build.sh

WORKDIR /
