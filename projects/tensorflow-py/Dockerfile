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

FROM sweetvishnya/ubuntu20.04-sydr-fuzz

MAINTAINER Darya Parygina (pa_darochek)

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        rsync \
        vim \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --upgrade pip

RUN python3 -m pip install --upgrade pyinstaller

# Due to Bazel bug, need to symlink python3 to python
# See https://github.com/bazelbuild/bazel/issues/8665
RUN ln -s /usr/local/bin/python3 /usr/local/bin/python

# Install Bazelisk to keep bazel in sync with the version required by TensorFlow
RUN curl -Lo /usr/bin/bazel \
        https://github.com/bazelbuild/bazelisk/releases/download/v1.1.0/bazelisk-linux-amd64 \
        && \
    chmod +x /usr/bin/bazel

RUN git clone --depth 1 https://github.com/tensorflow/tensorflow tensorflow

WORKDIR /tensorflow

COPY build.sh /

RUN /build.sh

COPY *_fuzz.py /tensorflow/tensorflow/tensorflow_src/security/fuzzing/

RUN chmod +x /tensorflow/tensorflow/tensorflow_src/security/fuzzing/*_fuzz.py
