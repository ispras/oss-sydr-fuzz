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

ARG BASE_IMAGE="sydr/ubuntu22.04-sydr-fuzz"
FROM $BASE_IMAGE

# Install deps
RUN apt-get update && \
    apt-get install -y libuv1 libuv1-dev

# Clone target from GitHub.
RUN git clone -b v2.13.0 https://github.com/pytorch/pytorch /pytorch

RUN cd /pytorch && \
    git submodule update --init --recursive

# Copy build script and targets.
COPY *.sh \
     *.patch \
     /
RUN mkdir src
COPY *.cc CMakeLists.txt /src

# Patch exceptions throwing to avoid unwanted crashes.
RUN ./patch_exceptions.sh

# Fix PyTorch build.
RUN rm /usr/bin/x86_64-linux-gnu-gcc && \
    ln -s /usr/bin/clang /usr/bin/x86_64-linux-gnu-gcc
RUN cd /pytorch/third_party/NNPACK && git apply /NNPACK_CMakeLists.patch
ENV PATH "/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/fuzz/sydr:/usr/local/go/bin:/root/go/bin:/root/.dotnet/tools"
RUN ln -s /usr/bin/python3 /usr/bin/python

# Install deps (without new cmake)
RUN cd /pytorch && \
    sed -i '/cmake*/d' requirements-build.txt && \
    pip3 install --group dev

# Build fuzz targets.
RUN TARGET="afl" /build.sh
RUN TARGET="sydr" /build.sh
RUN TARGET="fuzz" /build.sh
RUN TARGET="cov" /build.sh

# Prepare fuzzing corpus.
COPY ./ir_corpus.zip /
COPY ./parser_corpus.zip /
COPY ./corpus_message_deserialize.zip /
RUN mkdir corpus_torch_script && \
    find /pytorch -name "*.pt" -exec cp {} ./corpus_torch_script/ \; && \
    unzip /ir_corpus.zip && \
    unzip /parser_corpus.zip && \
    unzip /corpus_message_deserialize.zip
