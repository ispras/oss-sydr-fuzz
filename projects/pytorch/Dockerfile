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

MAINTAINER Theodor Arsenij Larionov-Trichkine

# Clone target from GitHub.
RUN pip3 install astunparse numpy ninja pyyaml mkl mkl-include setuptools cmake cffi typing_extensions && \
    git clone https://github.com/pytorch/pytorch/ /pytorch_fuzz && cd /pytorch_fuzz && \
    git checkout abc54f93145830b502400faa92bec86e05422fbd && \
    git submodule update --init --recursive --jobs 0

# Copy build script and targets.
COPY build_*.sh \
    *.patch \
    *_fuzz.cc \
    main-impl.cc \
    *.toml \
    patch_exceptions.sh \
    /

# Apply PyTorch fixes + copy for different targets.
RUN cd /pytorch_fuzz && \
    git apply /schema_type_parser-stoll.patch && \
    cp -r /pytorch_fuzz/ /pytorch_sydr/ && \
    cp -r /pytorch_fuzz/ /pytorch_cov/

# Patch exceptions throwing to avoid unwanted crashes.
RUN bash patch_exceptions.sh
WORKDIR /

# Build fuzz targets.
RUN bash build_fuzz.sh
RUN bash build_sydr.sh
RUN bash build_cov.sh

# Build reproducer for RPC bugs
RUN bash build_rpc_reproducer.sh

COPY ./ir_corpus.zip /
COPY ./parser_corpus.zip /
COPY ./corpus_message_deserialize.zip /
RUN mkdir corpus_torch_script && \
    find /pytorch_fuzz -name "*.pt" -exec cp {} ./corpus_torch_script/ \; && \
    unzip /ir_corpus.zip && \
    unzip /parser_corpus.zip && \
    unzip /corpus_message_deserialize.zip
