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

# Install build dependencies.
RUN pip3 install astunparse numpy ninja pyyaml mkl mkl-include setuptools cmake cffi typing_extensions

# Clone target from GitHub.
RUN git clone https://github.com/pytorch/pytorch /pytorch
RUN cd /pytorch && \
    git checkout aa89f0a1fd69c37d51ffc3b9b9449989761c6be9 && \
    git submodule update --init --recursive --jobs 0

# Copy build script and targets.
COPY *.sh \
     *.cc \
     /

# Patch exceptions throwing to avoid unwanted crashes.
RUN ./patch_exceptions.sh

# Fix PyTorch build.
RUN rm /usr/bin/x86_64-linux-gnu-gcc && \
    ln -s /usr/bin/clang /usr/bin/x86_64-linux-gnu-gcc

# Build fuzz targets.
RUN TARGET="afl" /build.sh
RUN TARGET="fuzz" /build.sh
RUN TARGET="sydr" /build.sh
RUN TARGET="cov" /build.sh

# Set large bitmap size for afl-showmap operation.
ENV AFL_MAP_SIZE=10000000

# Prepare fuzzing corpus.
COPY ./ir_corpus.zip /
COPY ./parser_corpus.zip /
COPY ./corpus_message_deserialize.zip /
RUN mkdir corpus_torch_script && \
    find /pytorch -name "*.pt" -exec cp {} ./corpus_torch_script/ \; && \
    unzip /ir_corpus.zip && \
    unzip /parser_corpus.zip && \
    unzip /corpus_message_deserialize.zip
