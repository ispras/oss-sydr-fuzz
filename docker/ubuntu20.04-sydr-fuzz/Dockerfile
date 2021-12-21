FROM ubuntu:20.04

MAINTAINER Alexey Vishnyakov

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y install build-essential cmake gcc-multilib g++-multilib git \
                       wget unzip clang-11 vim lsb-release gdb

RUN wget https://github.com/ninja-build/ninja/releases/download/v1.10.2/ninja-linux.zip \
    && unzip ninja-linux.zip && mv ninja /usr/bin && rm ninja-linux.zip

RUN git clone https://github.com/llvm/llvm-project.git && cd llvm-project && \
    git checkout de5b16d8ca2d14ff0d9b6be9cf40566bc7eb5a01 && \
    mkdir build && cd build && \
    cmake ../llvm -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_C_COMPILER=clang-11 \
                  -DCMAKE_C_COMPILER=clang-11 -DCMAKE_CXX_COMPILER=clang++-11 \
                  -DCMAKE_BUILD_TYPE=Release \
                  -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;compiler-rt" \
                  -GNinja && \
    CMAKE_BUILD_PARALLEL_LEVEL=15 cmake --build . && cmake --build . && \
    cmake --install . && cd ../.. && rm -rf llvm-project

ENV PATH=$PATH:/fuzz/sydr
