# Copyright 2021 Google LLC
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

RUN git clone https://github.com/lighttpd/lighttpd1.4
WORKDIR /lighttpd1.4
RUN git checkout 3b72817950d8ecc56ac3df9f9911e79993f2a868

COPY corpus.zip /
RUN cd / && unzip /corpus.zip
COPY build.sh fuzz_* /

RUN /build.sh

WORKDIR /
