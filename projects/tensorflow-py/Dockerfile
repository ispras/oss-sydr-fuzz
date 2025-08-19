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

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        rsync \
        vim \
        moreutils \
        patchelf \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade pyinstaller

# Due to Bazel bug, need to symlink python3 to python
# See https://github.com/bazelbuild/bazel/issues/8665
RUN ln -s /usr/bin/python3 /usr/local/bin/python

# Install Bazelisk to keep bazel in sync with the version required by TensorFlow
RUN curl -Lo /usr/bin/bazel \
        https://github.com/bazelbuild/bazelisk/releases/download/v1.1.0/bazelisk-linux-amd64 \
        && \
    chmod +x /usr/bin/bazel

RUN git clone https://github.com/tensorflow/tensorflow tensorflow && \
    cd tensorflow && git checkout v2.20.0

WORKDIR /tensorflow

COPY build.sh \
     *.patch \
     /

# Fix grpc build
RUN git apply /grpc.patch
RUN cp /fix_grpc_build.patch third_party/xla/third_party/grpc/.

RUN /build.sh

RUN mkdir /ld_path && ln $(find $(llvm-config --libdir) -name libclang_rt.asan-x86_64.so | head -1) /ld_path/libclang_rt.asan-x86_64.so

ENV LD_LIBRARY_PATH /ld_path

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
