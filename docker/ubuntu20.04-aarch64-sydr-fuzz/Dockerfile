FROM ubuntu:20.04

MAINTAINER Alexey Vishnyakov

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y build-essential gcc g++ gcc-9-plugin-dev \
        gcc-multilib-arm-linux-gnueabi g++-multilib-arm-linux-gnueabi \
        libglib2.0-dev libtool python3.9 python3.9-dev python3-pip \
        lsb-release pkg-config vim curl lcov gnuplot wget unzip m4 \
        software-properties-common zlib1g-dev git texinfo bison zip htop psutils

RUN rm /usr/bin/python3 && ln -s /usr/bin/python3.9 /usr/bin/python3
RUN pip3 install --upgrade pip

# Fix add-apt-repository for python3.9
RUN cd /usr/lib/python3/dist-packages && cp apt_pkg.cpython-38-aarch64-linux-gnu.so apt_pkg.so && \
    apt-get install -y libcairo2-dev libgirepository1.0-dev && \
    pip3 install --ignore-installed PyGObject && \
    sed -i 's/isAlive()/is_alive()/g' /usr/lib/python3/dist-packages/softwareproperties/SoftwareProperties.py

# Add clang repositories
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository -y ppa:ubuntu-toolchain-r/test
RUN add-apt-repository 'deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-14 main'

RUN wget http://ftp.us.debian.org/debian/pool/main/libf/libffi/libffi6_3.2.1-9_arm64.deb && \
    dpkg -i libffi6_3.2.1-9_arm64.deb && rm libffi6_3.2.1-9_arm64.deb

# Install binutils
RUN wget https://ftp.gnu.org/gnu/binutils/binutils-2.40.tar.xz && \
    tar xf binutils-*.tar.xz && rm binutils-*.tar.xz && cd binutils-* && \
    ./configure --prefix=/usr && make -j$(nproc) && make install && cd .. && \
    rm -rf binutils-*

# Install gdb
RUN wget https://ftp.gnu.org/gnu/gdb/gdb-12.1.tar.xz && \
    tar xf gdb-*.tar.xz && rm gdb-*.tar.xz && cd gdb-* && \
    ./configure --prefix=/usr && make -j$(nproc) && make install && cd .. && \
    rm -rf gdb-*

RUN apt update && \
    apt install -y gcc-10 g++-10 gcc-10-plugin-dev clang-14 clang-format-14 lld-14 \
                   libclang-rt-14-dev

RUN ln -s /usr/bin/clang-14 /usr/bin/clang && \
    ln -s /usr/bin/clang++-14 /usr/bin/clang++ && \
    ln -s /usr/bin/llvm-profdata-14 /usr/bin/llvm-profdata && \
    ln -s /usr/bin/llvm-cov-14 /usr/bin/llvm-cov && \
    ln -s /usr/bin/llvm-config-14 /usr/bin/llvm-config && \
    ln -s /usr/bin/llvm-symbolizer-14 /usr/bin/llvm-symbolizer

RUN python3 -m pip install coverage toml concurrencytest psutil

# Install Cmake
RUN curl -L -O https://github.com/Kitware/CMake/releases/download/v3.26.4/cmake-3.26.4-linux-aarch64.sh && \
    mkdir /cmake && \
    bash cmake-*.sh --prefix=/cmake --exclude-subdir --skip-license && \
    ln -s /cmake/bin/cmake /bin/cmake && \
    rm cmake-*.sh

# Install Ninja
RUN git clone https://github.com/ninja-build/ninja.git && cd ninja && \
    git checkout v1.11.1 && cmake -Bbuild-cmake && cmake --build build-cmake && \
    mv build-cmake/ninja /usr/bin && cd .. && rm -rf ninja

# Install Go
RUN wget https://go.dev/dl/go1.19.10.linux-arm64.tar.gz && \
    tar -C /root -xf go1.19.10.linux-arm64.tar.gz && \
    rm go1.19.10.linux-arm64.tar.gz

ENV GOPATH=/root/go
ENV PATH=$PATH:/root/.go/bin:$GOPATH/bin

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

RUN git clone https://github.com/google/atheris && cd atheris && \
    git checkout edf3eebfd028a2822db5037b8f95e5432990fd03 && \
    LIBFUZZER_LIB=/usr/lib/clang/14.0.6/lib/linux/libclang_rt.fuzzer_no_main-aarch64.a \
    MAKEFLAGS="-j$(nproc)" pip3 install . && \
    cd .. && rm -rf atheris

RUN git clone --depth=1 https://github.com/vanhauser-thc/afl-cov /afl-cov && cd /afl-cov && \
    make install -j $(nproc) && cd .. && rm -rf afl-cov

ENV LLVM_CONFIG=llvm-config-14
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV IS_DOCKER="1"

RUN git clone https://github.com/AFLplusplus/AFLplusplus.git && cd AFLplusplus && \
    git checkout v4.21c && export CC=clang-14 && export CXX=clang++-14 && \
    export LD_LIBRARY_PATH="$(llvm-config-14 --libdir)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" && make clean && \
    PERFORMANCE=1 make distrib -j $(nproc) && make install -j $(nproc) && make clean && cd .. && rm -rf AFLplusplus

# Install .NET, Sharpfuzz, minicover, altcover.
RUN wget https://download.visualstudio.microsoft.com/download/pr/092bec24-9cad-421d-9b43-458b3a7549aa/84280dbd1eef750f9ed1625339235c22/dotnet-sdk-8.0.101-linux-arm64.tar.gz
RUN mkdir /dotnet && tar zxf dotnet-sdk-8.0.101-linux-arm64.tar.gz -C /dotnet && rm -rf dotnet-sdk-8.0.101-linux-arm64.tar.gz
ENV DOTNET_ROOT=/dotnet
ENV PATH=$PATH:/dotnet
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_UPGRADEASSISTANT_TELEMETRY_OPTOUT=1
RUN dotnet tool install SharpFuzz.CommandLine --global
RUN dotnet tool install minicover --global
RUN dotnet tool install altcover.global --global
ENV PATH=$PATH:/root/.dotnet/tools

ENV PATH=$PATH:/fuzz/sydr

WORKDIR /
