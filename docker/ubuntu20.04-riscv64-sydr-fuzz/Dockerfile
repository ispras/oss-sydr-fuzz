FROM riscv64/ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y build-essential gcc g++ gcc-9-plugin-dev \
        libglib2.0-dev libtool python3.9 python3.9-dev python3-pip \
        lsb-release pkg-config vim curl lcov gnuplot wget unzip m4 \
        software-properties-common zlib1g-dev git texinfo bison zip \
        htop psutils clang-12 libssl-dev

RUN rm /usr/bin/python3 && ln -s /usr/bin/python3.9 /usr/bin/python3
RUN pip3 install --upgrade pip
RUN python3 -m pip install coverage toml concurrencytest psutil

# Install CMake
ENV PATH=/usr/lib/riscv64-linux-gnu:$PATH
RUN wget https://gitlab.kitware.com/cmake/cmake/-/archive/v3.26.0/cmake-v3.26.0.tar.gz && \
    tar -xf cmake-v3.26.0.tar.gz && rm cmake-v3.26.0.tar.gz && cd cmake-v3.26.0 && \
    export CC=clang-12 && export CXX=clang++-12 && ./bootstrap --parallel=`nproc` && \
    make -j$(nproc) && make install && cd .. && rm -rf cmake-v3.26.0

# Install Ninja
RUN git clone https://github.com/ninja-build/ninja.git && cd ninja && \
    git checkout v1.11.1 && export CC=clang-12 && export CXX=clang++-12 && \
    export CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) && cmake -Bbuild-cmake && \
    cmake --build build-cmake && mv build-cmake/ninja /usr/bin && \
    cd .. && rm -rf ninja

# Install binutils
RUN wget https://ftp.gnu.org/gnu/binutils/binutils-2.40.tar.xz && \
    tar xf binutils-*.tar.xz && rm binutils-*.tar.xz && cd binutils-* && \
    ./configure --prefix=/usr && make -j$(nproc) && make install && cd .. && \
    rm -rf binutils-*

RUN wget -q https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-15.0.7.tar.gz && \
    tar xf llvmorg-*.tar.gz && rm llvmorg-*.tar.gz && cd llvm-project* && \
    sed -i '41s/.*/  set(ALL_FUZZER_SUPPORTED_ARCH ${X86} ${X86_64} ${ARM32} ${ARM64} ${S390X} ${RISCV64})/' compiler-rt/cmake/Modules/AllSupportedArchDefs.cmake && \
    mkdir build && cd build && \
    cmake \
        -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_C_COMPILER=clang-12 \
        -DCMAKE_CXX_COMPILER=clang++-12 \
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
        -GNinja  ../llvm/
RUN cat //llvm-project-llvmorg-15.0.7/compiler-rt/cmake/Modules/AllSupportedArchDefs.cmake
RUN cd /llvm-project-llvmorg-15.0.7/build && \
    CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build . && \
    cmake --install . && cd ../.. && rm -rf llvm-project

# Install Go
RUN wget https://go.dev/dl/go1.23.3.linux-riscv64.tar.gz && \
    tar -C /root -xf go1.23.3.linux-riscv64.tar.gz && \
    rm go1.23.3.linux-riscv64.tar.gz
ENV PATH=$PATH:/root/.go/bin:/root/go/bin
RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest

# Install Rust.
RUN curl https://sh.rustup.rs | sh -s -- -y --default-toolchain=nightly --profile=minimal
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-fuzz
RUN cargo install afl@0.13.5
RUN rustup component add llvm-tools-preview
RUN rustup component add rust-src --toolchain nightly
RUN rustup component add rustfmt clippy

ADD https://raw.githubusercontent.com/vanhauser-thc/qemu_driver/master/qemu_driver.c /opt/
ADD https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c /opt/

# Install atheris
RUN git clone https://github.com/google/atheris && cd atheris && \
    LIBFUZZER_LIB=/usr/lib/clang/15.0.7/lib/riscv64-unknown-linux-gnu/libclang_rt.fuzzer_no_main.a \
    MAKEFLAGS="-j$(nproc)" pip3 install . && \
    cd .. && rm -rf atheris

# Install AFL++
RUN git clone --depth=1 https://github.com/vanhauser-thc/afl-cov /afl-cov && cd /afl-cov && \
    make install -j $(nproc) && cd .. && rm -rf afl-cov

ENV LLVM_CONFIG=llvm-config
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV IS_DOCKER="1"

RUN git clone https://github.com/AFLplusplus/AFLplusplus.git && cd AFLplusplus && \
    git checkout v4.21c && export CC=clang && export CXX=clang++ && \
    export LD_LIBRARY_PATH="$(llvm-config --libdir)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" && make clean && \
    PERFORMANCE=1 make distrib -j $(nproc) && make install -j $(nproc) && make clean && cd .. && rm -rf AFLplusplus

# Install gdb
RUN wget https://ftp.gnu.org/gnu/gdb/gdb-15.2.tar.xz && \
    tar xf gdb-*.tar.xz && rm gdb-*.tar.xz && cd gdb-* && \
    export CC=clang && export CXX=clang++ && \
    ./configure --prefix=/usr && make -j$(nproc) && make install && cd .. && \
    rm -rf gdb-*

ENV PATH=$PATH:/fuzz/sydr

WORKDIR /
