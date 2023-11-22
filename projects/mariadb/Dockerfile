# Copyright 2023 Google LLC
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

RUN apt-get install -y libncurses5-dev gnutls-dev bison zlib1g-dev ccache \
    curl bzip2 lz4 liblzma-dev

RUN git clone https://github.com/MariaDB/server && cd server && \
    git checkout 94eb819296c99b2f1d1a68a5a12eabe18e2f4874

WORKDIR /

COPY build.sh *.c json.dict corpus.zip /

RUN CONFIG="libfuzzer" /build.sh
RUN CONFIG="afl" /build.sh
RUN CONFIG="sydr" /build.sh
RUN CONFIG="coverage" /build.sh

RUN unzip corpus.zip -d /corpus
