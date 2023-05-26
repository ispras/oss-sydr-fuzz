# Copyright 2023 ISP RAS
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

RUN apt-get update && apt install build-essential git gettext \
                      flex bison libtool autoconf automake pkg-config \
                      libnuma-dev libpcre2-dev \
		      libmaxminddb-dev librrd-dev -y

RUN git clone https://github.com/ntop/nDPI.git
RUN git clone --depth 1 https://github.com/json-c/json-c.git json-c
ADD https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz libpcap-1.9.1.tar.gz

RUN mkdir corpus && mv nDPI/tests/cfgs/default/pcap/* corpus

WORKDIR nDPI

RUN git checkout 334b43579e2b1aa4bffa11c4014c4e1fd0b60ba5

COPY build.sh load_sydr_process_packet.c load_sydr_ndpi_reader.c load_sydr_quic_get_crypto_data.c load_sydr_tls_certificate.c ./

RUN ./build.sh

WORKDIR /
