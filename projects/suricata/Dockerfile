# Copyright 2019 Google Inc.
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

RUN apt-get update && apt-get install -y autoconf automake libtool make pkg-config \
					python flex bison libmagic-dev libcap-ng-dev libyaml-dev libjansson-dev libpcap-dev
RUN cargo install --force cbindgen

RUN git init && git remote add origin https://github.com/koltiradw/suricata_fuzz_corpus.git && \
		git fetch origin && git checkout main && rm -rf .git

RUN mkdir SRC

WORKDIR /SRC

ADD https://github.com/PhilipHazel/pcre2/releases/download/pcre2-10.39/pcre2-10.39.tar.gz pcre2-10.39.tar.gz
ADD http://www.digip.org/jansson/releases/jansson-2.12.tar.gz jansson-2.12.tar.gz
ADD https://github.com/lz4/lz4/archive/v1.9.2.tar.gz lz4-1.9.2.tar.gz
RUN git clone --depth 1 -b develop https://github.com/madler/zlib.git
RUN git clone --depth=1 https://github.com/catenacyber/fuzzpcap

RUN git clone --depth 1 https://github.com/OISF/suricata.git suricata && \
				cd suricata && git checkout af4bb917dc9842229445683b5ce2f955faa464c2
RUN git clone --depth 1 https://github.com/OISF/libhtp.git libhtp


COPY targets/*.c /SRC/suricata/src/tests/fuzz/
COPY build.sh .

RUN ./build.sh
