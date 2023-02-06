FROM ubuntu:20.04

MAINTAINER Alexey Vishnyakov

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y install build-essential gcc-multilib g++-multilib git \
                       wget curl unzip clang-11 vim lsb-release zlib1g-dev \
                       lcov pkg-config libglib2.0-dev gcc-10 g++-10 \
                       gcc-10-plugin-dev gcc-10-multilib python3 python3-pip \
                       libtool gnuplot binutils-dev

RUN wget https://ftp.gnu.org/gnu/gdb/gdb-12.1.tar.xz && tar xf gdb-*.tar.xz && \
    cd gdb-* && ./configure && make -j$(nproc) && make install && cd .. && \
    rm -rf gdb-*

RUN python3 -m pip install scipy numpy coverage toml

RUN curl -L -O https://github.com/Kitware/CMake/releases/download/v3.22.1/cmake-3.22.1-linux-x86_64.sh && \
    mkdir /cmake && \
    bash cmake-3.22.1-linux-x86_64.sh --prefix=/cmake --exclude-subdir --skip-license && \
    ln -s /cmake/bin/cmake /bin/cmake && \
    rm cmake-3.22.1-linux-x86_64.sh

# Install Rust.
RUN curl https://sh.rustup.rs | sh -s -- -y --default-toolchain=nightly --profile=minimal

ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo install cargo-fuzz

RUN cargo install afl

RUN rustup component add llvm-tools-preview

RUN rustup component add rust-src --toolchain nightly

RUN wget https://github.com/ninja-build/ninja/releases/download/v1.10.2/ninja-linux.zip \
    && unzip ninja-linux.zip && mv ninja /usr/bin && rm ninja-linux.zip

RUN git clone https://github.com/llvm/llvm-project.git && cd llvm-project && \
    git checkout de5b16d8ca2d14ff0d9b6be9cf40566bc7eb5a01 && \
    mkdir build && cd build && \
    cmake \
        -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_C_COMPILER=clang-11 \
        -DCMAKE_CXX_COMPILER=clang++-11 \
        -DCLANG_INCLUDE_DOCS="OFF" \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_BINUTILS_INCDIR=/usr/include/ \
        -DLLVM_BUILD_LLVM_DYLIB="ON" \
        -DLLVM_ENABLE_ZLIB=ON \
        -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
        -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;lld;clang-tools-extra" \
        -DLLVM_ENABLE_WARNINGS="OFF" \
        -DLLVM_INCLUDE_BENCHMARKS="OFF" \
        -DLLVM_INCLUDE_DOCS="OFF" \
        -DLLVM_INCLUDE_EXAMPLES="OFF" \
        -DLLVM_INCLUDE_TESTS="OFF" \
        -DLLVM_LINK_LLVM_DYLIB="ON" \
        -GNinja  ../llvm/ && \
    CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build . && \
    cmake --install . && cd ../.. && rm -rf llvm-project

RUN echo /usr/lib/x86_64-unknown-linux-gnu > /etc/ld.so.conf.d/libc++.conf && \
    ldconfig

RUN git clone --depth=1 https://github.com/vanhauser-thc/afl-cov /afl-cov && cd /afl-cov && \
    make install -j $(nproc) && cd .. && rm -rf afl-cov

ENV LLVM_CONFIG=llvm-config
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV IS_DOCKER="1"

RUN git clone https://github.com/AFLplusplus/AFLplusplus.git && cd AFLplusplus && \
    git checkout 4.05c && export CC=clang && export CXX=clang++ && \
    export LD_LIBRARY_PATH="$(llvm-config --libdir)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" && make clean && \
    make distrib -j $(nproc) && make install -j $(nproc) && make clean && cd .. && rm -rf AFLplusplus

ENV PATH=$PATH:/fuzz/sydr

RUN git clone https://github.com/google/atheris && cd atheris && pip3 install . && cd .. && rm -rf atheris

ADD https://raw.githubusercontent.com/vanhauser-thc/qemu_driver/master/qemu_driver.c /opt/
ADD https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c /opt/

WORKDIR /
