FROM ubuntu:20.04

MAINTAINER Alexey Vishnyakov

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y install build-essential gcc-multilib g++-multilib git \
                       wget curl unzip clang-11 vim lsb-release zlib1g-dev \
                       lcov pkg-config libglib2.0-dev gcc-10 g++-10 \
                       gcc-10-plugin-dev gcc-10-multilib python3.9 python3.9-dev \
                       python3-pip libtool gnuplot binutils-dev zip htop psutils openjdk-17-jdk

RUN rm /usr/bin/python3 && ln -s /usr/bin/python3.9 /usr/bin/python3
RUN pip3 install --upgrade pip

RUN wget https://ftp.gnu.org/gnu/gdb/gdb-12.1.tar.xz && tar xf gdb-*.tar.xz && \
    cd gdb-* && ./configure && make -j$(nproc) && make install && cd .. && \
    rm -rf gdb-*

RUN python3 -m pip install coverage toml concurrencytest psutil

RUN curl -L -O https://github.com/Kitware/CMake/releases/download/v3.26.4/cmake-3.26.4-linux-x86_64.sh && \
    mkdir /cmake && \
    bash cmake-*.sh --prefix=/cmake --exclude-subdir --skip-license && \
    ln -s /cmake/bin/cmake /bin/cmake && \
    rm cmake-*.sh

# Install Rust.
RUN curl https://sh.rustup.rs | sh -s -- -y --default-toolchain=nightly --profile=minimal

ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo install cargo-fuzz

RUN cargo install afl@0.13.5

RUN rustup component add llvm-tools-preview

RUN rustup component add rust-src --toolchain nightly

RUN rustup component add rustfmt clippy

RUN wget https://github.com/ninja-build/ninja/releases/download/v1.10.2/ninja-linux.zip \
    && unzip ninja-linux.zip && mv ninja /usr/bin && rm ninja-linux.zip

RUN wget -q https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-14.0.6.tar.gz && \
    tar xf llvmorg-*.tar.gz && rm llvmorg-*.tar.gz && cd llvm-project* && \
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
    git checkout v4.21c && export CC=clang && export CXX=clang++ && \
    export LD_LIBRARY_PATH="$(llvm-config --libdir)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" && make clean && \
    PERFORMANCE=1 make distrib -j $(nproc) && make install -j $(nproc) && make clean && cd .. && rm -rf AFLplusplus

ENV PATH=$PATH:/fuzz/sydr

RUN git clone https://github.com/google/atheris && cd atheris && \
    git checkout edf3eebfd028a2822db5037b8f95e5432990fd03 && \
    pip3 install . && cd .. && rm -rf atheris

ADD https://raw.githubusercontent.com/vanhauser-thc/qemu_driver/master/qemu_driver.c /opt/
ADD https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c /opt/

# Install Go
RUN curl --silent -O https://storage.googleapis.com/golang/getgo/installer_linux && \
    chmod +x ./installer_linux && \
    SHELL="bash" ./installer_linux -version=1.19 && \
    rm -rf ./installer_linux

ENV GOPATH=/root/go
ENV PATH=$PATH:/root/.go/bin:$GOPATH/bin

RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest

# Install Jazzer
RUN curl -L https://github.com/bazelbuild/bazelisk/releases/download/v1.9.0/bazelisk-linux-amd64 -o /usr/local/bin/bazel && \
    chmod +x /usr/local/bin/bazel
RUN git clone https://github.com/CodeIntelligenceTesting/jazzer.git && cd jazzer && \
    bazel build --java_runtime_version=local_jdk_17 -c opt \
    --cxxopt="-stdlib=libc++" --linkopt=-lc++ //:jazzer_release && \
    cp -L ./bazel-out/k8-opt/bin/src/main/java/com/code_intelligence/jazzer/jazzer_standalone_deploy.jar \
        /usr/local/lib/jazzer_standalone_deploy.jar && \
    cp -L ./bazel-out/k8-opt/bin/launcher/jazzer /usr/local/bin/ && cd .. && rm -rf jazzer

# Install jacoco lib for java coverage
RUN mkdir /usr/local/lib/jacoco && cd /usr/local/lib/jacoco && \
    wget https://github.com/jacoco/jacoco/releases/download/v0.8.10/jacoco-0.8.10.zip && \
    unzip jacoco*.zip && rm -rf jacoco*.zip

# Install Node.js and Jazzer.js
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    export NODE_MAJOR=20 && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list && \
    apt update && apt install -y nodejs
RUN git clone --depth 1 -b v2.1.0 https://github.com/CodeIntelligenceTesting/jazzer.js
WORKDIR /jazzer.js
RUN npm install && \
    npm run build && \
    npm install --save-dev

# Install .NET, Sharpfuzz, minicover, altcover
RUN wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        dotnet-sdk-8.0
RUN dotnet tool install SharpFuzz.CommandLine --global
RUN dotnet tool install minicover --global
RUN dotnet tool install altcover.global --global
ENV PATH=$PATH:/root/.dotnet/tools

WORKDIR /
