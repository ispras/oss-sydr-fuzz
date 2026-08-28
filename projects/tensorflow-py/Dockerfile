# Copyright 2021 Google Inc.
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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN apt-get update && apt-get -y install rsync curl moreutils patchelf
RUN apt-get install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev \
    libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev

# Install Python3.10
RUN wget https://www.python.org/ftp/python/3.10.11/Python-3.10.11.tgz
RUN tar -xvf Python-3.10.11.tgz && rm Python-3.10.11.tgz
WORKDIR /Python-3.10.11
RUN ./configure --enable-optimizations && \
    make -j$(nproc) && make install -j$(nproc)
RUN pip3 install --upgrade pip
RUN python3 -m pip install --upgrade pyinstaller
RUN python3 -m pip install numpy toml

# Install atheris
RUN git clone https://github.com/google/atheris && cd atheris && \
    git checkout cbf4ad989dcb4d3ef42152990ed89cfceb50e059 && \
    pip3 install . && cd .. && rm -rf atheris

# Due to Bazel bug, need to symlink python3 to python
# See https://github.com/bazelbuild/bazel/issues/8665
RUN ln -s /usr/local/bin/python3 /usr/local/bin/python

# Fixup old python in /usr/bin
RUN rm /usr/bin/python3 && \
    ln -s /usr/local/bin/python3 /usr/bin/python3 && \
    ln -s /usr/local/bin/python3 /usr/bin/python

# Install Bazelisk to keep bazel in sync with the version required by TensorFlow
RUN curl -Lo /usr/bin/bazel \
        https://github.com/bazelbuild/bazelisk/releases/download/v1.1.0/bazelisk-linux-amd64 \
        && \
    chmod +x /usr/bin/bazel

# Prepare sources
WORKDIR /
RUN git clone -b v2.21.0 https://github.com/tensorflow/tensorflow tensorflow

WORKDIR /tensorflow

COPY build.sh \
     *.patch \
     /

# Fix grpc build
RUN git apply /grpc.patch
RUN cp /fix_grpc_build.patch third_party/xla/third_party/grpc/.

RUN /build.sh

RUN mkdir /ld_path && ln $(find /usr/lib/llvm-18 -name libclang_rt.asan-x86_64.so | head -1) /ld_path/libclang_rt.asan-x86_64.so

ENV LD_LIBRARY_PATH=/ld_path

RUN for file in `ls /tensorflow/tensorflow/security/fuzzing/*_fuzz.py`; do (echo "#!/usr/bin/env python3"; cat "$file") | sponge "$file"; done

RUN chmod +x /tensorflow/tensorflow/security/fuzzing/*_fuzz.py

WORKDIR /

COPY *.py *.zip /

# Prepare initial corporas.
RUN cp -r /tensorflow/tensorflow/core/kernels/fuzzing/corpus /

RUN cd /corpus && \
    unzip /encode_wav.zip && unzip /load_model.zip

# Prepare dictionaries
RUN cp -r /tensorflow/tensorflow/core/kernels/fuzzing/dictionaries /dicts 
