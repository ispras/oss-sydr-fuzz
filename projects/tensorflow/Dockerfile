# Copyright 2018 Google Inc.
# Modifications copyright (C) 2021 ISP RAS
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

COPY main.c /
COPY install_java.sh /usr/local/bin/

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        rsync \
	gdb \
	pip \
	lld \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install numpy

# Install Bazel through Bazelisk, which automatically fetches the latest Bazel version.
ENV BAZELISK_VERSION 1.9.0
RUN curl -L https://github.com/bazelbuild/bazelisk/releases/download/v$BAZELISK_VERSION/bazelisk-linux-amd64 -o /usr/local/bin/bazel && \
    chmod +x /usr/local/bin/bazel

# Due to Bazel bug, need to symlink python3 to python
# See https://github.com/bazelbuild/bazel/issues/8665
RUN ln -s /usr/local/bin/python3 /usr/local/bin/python

# Install Bazelisk to keep bazel in sync with the version required by TensorFlow
RUN curl -Lo /usr/bin/bazel \
        https://github.com/bazelbuild/bazelisk/releases/download/v1.1.0/bazelisk-linux-amd64 \
        && \
    chmod +x /usr/bin/bazel

# Setup the environment.
ENV CC "clang"
ENV CXX "clang++"
ENV CCC "clang++"

ENV CFLAGS "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
ENV CXXFLAGS_EXTRA "-stdlib=libc++"
ENV CXXFLAGS "$CFLAGS $CXXFLAGS_EXTRA"

ENV JAVA_HOME /usr/lib/jvm/java-15-openjdk-amd64
# it fails after installing java due to jazzer env variables missing
RUN install_java.sh || true

WORKDIR /
RUN git clone https://github.com/tensorflow/tensorflow tensorflow
WORKDIR /tensorflow
RUN git checkout b56e6db5e7cccfffa824bbc1b5e018c6cc413c21
COPY build_fuzz.sh /

RUN bash /build_fuzz.sh
WORKDIR /
RUN rm -rf tensorflow

RUN git clone https://github.com/tensorflow/tensorflow tensorflow
WORKDIR /tensorflow
RUN git checkout b56e6db5e7cccfffa824bbc1b5e018c6cc413c21
COPY build_sydr.sh /

RUN bash /build_sydr.sh

