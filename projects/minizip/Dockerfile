# Copyright 2018 Google Inc.
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
RUN apt-get update && apt-get install -y make cmake pkg-config libssl-dev 

RUN git clone -b develop https://github.com/zlib-ng/minizip-ng 
RUN cd minizip-ng && \
    git fetch && \
    git checkout 46673f533357ad57400020a263e09455033f4eb7 && \
    cd ..
WORKDIR minizip-ng
COPY build.sh /
RUN /build.sh
RUN mkdir /unzip_fuzzer_corpus && find /minizip-ng/test/fuzz/unzip_fuzzer_seed_corpus -name "*.zip" | xargs -I {} cp {} /unzip_fuzzer_corpus 

