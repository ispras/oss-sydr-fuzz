# Copyright 2018 Google Inc.
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

RUN apt-get update && apt-get -y install rsync

RUN python3 -m pip install numpy

# Due to Bazel bug, need to symlink python3 to python
# See https://github.com/bazelbuild/bazel/issues/8665
RUN ln -s /usr/local/bin/python3 /usr/local/bin/python

# Install Bazelisk to keep bazel in sync with the version required by TensorFlow
RUN curl -Lo /usr/bin/bazel \
        https://github.com/bazelbuild/bazelisk/releases/download/v1.1.0/bazelisk-linux-amd64 \
        && \
    chmod +x /usr/bin/bazel

COPY *.patch *.sh *.cc *.c /

ENV JAVA_HOME /usr/lib/jvm/java-15-openjdk-amd64
# it fails after installing java due to jazzer env variables missing, it's ok.
RUN /install_java.sh || true

# Setup the environment.
ENV TF_CPP_MIN_LOG_LEVEL=3

# Build custom afl-cc to increase MAX_PARAMS_NUM.
RUN /build_afl_cc.sh

# Prepare sources
WORKDIR /
RUN git clone https://github.com/tensorflow/tensorflow tensorflow_afl && \
    cd /tensorflow_afl && \
    git checkout v2.20.0-rc0
# Revert 4642e0b57f172c88172578b74ed9019c4d346a07 that brokes fuzzing
RUN cd /tensorflow_afl && git apply tensorflow.patch
RUN cp -r /tensorflow_afl /tensorflow_fuzz && \
    cp -r tensorflow_afl tensorflow_sydr && \
    cp -r tensorflow_afl tensorflow_cov
COPY fuzz_session.h /tensorflow_sydr/tensorflow/core/kernels/fuzzing/fuzz_session.h
COPY fuzz_session.h /tensorflow_cov/tensorflow/core/kernels/fuzzing/fuzz_session.h

RUN cd /tensorflow_afl && CONFIG=afl /build.sh
RUN cd /tensorflow_fuzz && CONFIG=libfuzzer /build.sh
RUN cd /tensorflow_sydr && CONFIG=sydr /build.sh
RUN cd /tensorflow_cov && CONFIG=coverage /build.sh

# Fix coverage paths, because bazel builds the project in isolated environment.
# Probably don't touch, it works.
RUN /fix_cov.sh

# Prepare corporas and dictionaries.
RUN cp -r /tensorflow_afl/tensorflow/core/kernels/fuzzing/corpus /
RUN cp -r /tensorflow_afl/tensorflow/core/kernels/fuzzing/dictionaries /

COPY corpus/*.zip /

WORKDIR /corpus
RUN find / -maxdepth 1 -name '*.zip' -exec bash -c "unzip {} && rm {}" \;

# Increase timeout for forkserver spin up.
ENV AFL_FORKSRV_INIT_TMOUT=1200000

# Set large bitmap size for afl-showmap operation.
ENV AFL_MAP_SIZE=100000000

WORKDIR /
