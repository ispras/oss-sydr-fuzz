# Copyright 2024 ISP RAS
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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN apt-get update && apt-get install -y binutils make ninja-build \
    liblzma-dev libz-dev pkg-config autoconf libtool

RUN git clone --depth 1 https://github.com/open-source-parsers/jsoncpp
RUN git clone --depth 1 https://github.com/nlohmann/json_test_data

WORKDIR jsoncpp

RUN git clone --depth 1 https://github.com/google/libprotobuf-mutator.git

RUN (mkdir LPM && cd LPM && cmake ../libprotobuf-mutator -GNinja -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON \
    -DLIB_PROTO_MUTATOR_TESTING=OFF -DCMAKE_BUILD_TYPE=Release && ninja)

COPY build.sh .
RUN mkdir /proto
COPY *.proto *.h *.cc packer/* /proto/
COPY *.dict /

RUN ./build.sh

WORKDIR /json_test_data

RUN git checkout a1375cea09d27cc1c4cadb8d00470375b421ac37
RUN mkdir /corpus && find /json_test_data -size -5k -name "*.json" -exec cp "{}" "/corpus" \;

WORKDIR /

RUN rm -rf json_test_data
# remove empty file from corpus
RUN rm corpus/n_structure_no_data.json

COPY prepare_corpus.sh /prepare_corpus.sh
RUN /prepare_corpus.sh
