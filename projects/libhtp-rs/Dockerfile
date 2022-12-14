# Copyright 2022 ISP RAS
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

RUN rustup install nightly
RUN cargo install cargo-fuzz
RUN cargo install afl

RUN git clone https://github.com/cccs-rtmorti/libhtp-rs.git

WORKDIR /libhtp-rs

RUN git checkout 2bef6f30c916fdd057a15434466ea432b0bbf17c

RUN mkdir /corpus && cp /libhtp-rs/tests/files/*.t /corpus

RUN mkdir -p /libhtp-rs/afl

WORKDIR /

COPY build.sh http.dict ./
COPY afl/ /libhtp-rs/afl/
COPY sydr_and_cover/ /libhtp-rs/sydr_and_cover/

RUN bash build.sh
