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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN git clone https://github.com/syoyo/tinygltf.git && cd tinygltf && \
    git checkout 6782f887bb100e2bc7e6751ad46fe8288c84f767
RUN git clone https://github.com/KhronosGroup/glTF-Sample-Models.git gltf-corpus && \
    cd gltf-corpus && git checkout c659bd7d714b74e84f33345cb6365599f2cd0518

WORKDIR /

COPY build.sh json.dict loader_example.cc /

RUN CONFIG="libfuzzer" /build.sh
RUN CONFIG="afl" /build.sh
RUN CONFIG="sydr" /build.sh
RUN CONFIG="coverage" /build.sh

RUN mkdir /corpus && cp -R -f -n gltf-corpus/2.0/*/glTF/*.gltf \
    tinygltf/models/*/*.gltf gltf-corpus/1.0/*/glTF/*.gltf /corpus
