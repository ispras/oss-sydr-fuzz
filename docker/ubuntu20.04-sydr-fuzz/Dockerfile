FROM ubuntu:20.04

MAINTAINER Alexey Vishnyakov

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y install build-essential gcc-multilib g++-multilib git \
                       wget curl unzip clang-11 vim lsb-release gdb zlib1g-dev \
                       lcov pkg-config libglib2.0-dev gcc-10 g++-10 \
                       gcc-10-plugin-dev gcc-10-multilib python3 python3-pip \
                       libtool gnuplot

RUN python3 -m pip install scipy numpy

RUN curl -L -O https://github.com/Kitware/CMake/releases/download/v3.22.1/cmake-3.22.1-linux-x86_64.sh && \
    mkdir /cmake && \
    bash cmake-3.22.1-linux-x86_64.sh --prefix=/cmake --exclude-subdir --skip-license && \
    ln -s /cmake/bin/cmake /bin/cmake && \
    rm cmake-3.22.1-linux-x86_64.sh

# Install Rust.
RUN curl https://sh.rustup.rs -o rustup.sh && chmod +x rustup.sh && \
    ./rustup.sh -y && rm rustup.sh

ENV PATH="/root/.cargo/bin:${PATH}"

RUN wget https://github.com/ninja-build/ninja/releases/download/v1.10.2/ninja-linux.zip \
    && unzip ninja-linux.zip && mv ninja /usr/bin && rm ninja-linux.zip

RUN git clone https://github.com/llvm/llvm-project.git && cd llvm-project && \
    git checkout de5b16d8ca2d14ff0d9b6be9cf40566bc7eb5a01 && \
    mkdir build && cd build && \
    cmake ../llvm -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_C_COMPILER=clang-11 \
                  -DCMAKE_C_COMPILER=clang-11 -DCMAKE_CXX_COMPILER=clang++-11 \
                  -DCMAKE_BUILD_TYPE=Release \
                  -DLLVM_ENABLE_ZLIB=ON \
                  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
                  -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;compiler-rt" \
                  -GNinja && \
    CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build . && cmake --build . && \
    cmake --install . && cd ../.. && rm -rf llvm-project

RUN echo /usr/lib/x86_64-unknown-linux-gnu > /etc/ld.so.conf.d/libc++.conf && \
    ldconfig

RUN git clone --depth=1 https://github.com/vanhauser-thc/afl-cov /afl-cov && cd /afl-cov && \
    git checkout bb51de02c06dca2bfa2dfb494fa3b095950ec879 && \
    make install -j $(nproc) && cd .. && rm -rf afl-cov

ENV LLVM_CONFIG=llvm-config
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV IS_DOCKER="1"

RUN git clone https://github.com/AFLplusplus/AFLplusplus.git && cd AFLplusplus && \
    git checkout 40947508037b874020c8dd1251359fecaab04b9d && \
    export CC=gcc-10 && export CXX=g++-10 && make clean && \
    make distrib -j $(nproc) && make install -j $(nproc) && make clean && cd .. && rm -rf AFLplusplus

ENV PATH=$PATH:/fuzz/sydr

WORKDIR /
