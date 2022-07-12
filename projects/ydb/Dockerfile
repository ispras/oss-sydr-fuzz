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

MAINTAINER Andrey Fedotov

# Install build dependencies.
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc | apt-key add -
RUN echo 'deb http://apt.kitware.com/ubuntu/ focal main' | tee /etc/apt/sources.list.d/kitware.list >/dev/null
RUN echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal main' | tee /etc/apt/sources.list.d/llvm.list >/dev/null

RUN apt-get update && \
    apt-get install -y make git cmake python python3-pip ninja-build antlr3\
                       m4 clang-12 lld-12 libidn11-dev libaio1 libaio-dev
RUN pip3 install conan

# Clone target from GitHub.
RUN mkdir /ydbwork
WORKDIR ydbwork
RUN git clone https://github.com/ydb-platform/ydb.git

# Fix commit
RUN cd ydb && git checkout 250d29abfdc9a2526cac1e0b4b36c5b6e1d58e0c

# Build project for libFuzzer.
RUN mkdir build-fuzz
COPY fuzzer.diff ./
RUN  cd ydb && git apply ../fuzzer.diff
RUN cd build-fuzz && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../ydb/clang.toolchain ../ydb && \
    ninja -j$(nproc)

# Build projetc for Sydr.
RUN mkdir build-sydr
COPY sydr.cc ./ydb
RUN cd ydb && git checkout .
COPY sydr.diff ./
RUN  cd ydb && git apply ../sydr.diff

RUN cd build-sydr && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../ydb/clang.toolchain ../ydb && \
    ninja -j$(nproc)

# Build project for coverage.
#RUN mkdir build-cov
#RUN cd ydb && git checkout .
#COPY cov.diff ./
#RUN  cd ydb && git apply ../cov.diff

#RUN cd build-cov && \
#    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../ydb/clang.toolchain ../ydb && \
#    ninja -j100
