FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y install build-essential gcc-11 g++-11 gcc-11-multilib g++-11-multilib \
                       wget curl unzip clang-11 vim lsb-release zlib1g-dev \
                       lcov pkg-config libglib2.0-dev gcc-11-plugin-dev git \
                       python3.10 python3.10-dev libglib2.0-dev lld llvm-dev \
                       python3-pip libtool gnuplot binutils-dev zip htop psutils \
                       openjdk-17-jdk file libssl-dev lua5.1 liblua5.1-dev \
                       automake autoconf libpixman-1-dev bison flex meson texinfo \
                       software-properties-common gnupg gpg libtbb-dev

RUN dpkg --add-architecture i386 && \
    apt update && apt install -y zlib1g:i386 zlib1g-dev:i386

RUN rm /usr/bin/python3 && ln -s /usr/bin/python3.10 /usr/bin/python3
RUN pip3 install --upgrade pip

RUN wget https://ftp.gnu.org/gnu/gdb/gdb-12.1.tar.xz && tar xf gdb-*.tar.xz && \
    cd gdb-* && ./configure && make -j$(nproc) && make install && cd .. && \
    rm -rf gdb-*

# Install LLVM-18
RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN ./llvm.sh 18 all
ARG version=18
ARG priority=1
RUN update-alternatives \
    --verbose \
    --install /usr/bin/llvm-config       llvm-config      /usr/bin/llvm-config-${version} ${priority} \
    --slave   /usr/bin/llvm-ar           llvm-ar          /usr/bin/llvm-ar-${version} \
    --slave   /usr/bin/llvm-as           llvm-as          /usr/bin/llvm-as-${version} \
    --slave   /usr/bin/llvm-bcanalyzer   llvm-bcanalyzer  /usr/bin/llvm-bcanalyzer-${version} \
    --slave   /usr/bin/llvm-cov          llvm-cov         /usr/bin/llvm-cov-${version} \
    --slave   /usr/bin/llvm-diff         llvm-diff        /usr/bin/llvm-diff-${version} \
    --slave   /usr/bin/llvm-dis          llvm-dis         /usr/bin/llvm-dis-${version} \
    --slave   /usr/bin/llvm-dwarfdump    llvm-dwarfdump   /usr/bin/llvm-dwarfdump-${version} \
    --slave   /usr/bin/llvm-extract      llvm-extract     /usr/bin/llvm-extract-${version} \
    --slave   /usr/bin/llvm-link         llvm-link        /usr/bin/llvm-link-${version} \
    --slave   /usr/bin/llvm-mc           llvm-mc          /usr/bin/llvm-mc-${version} \
    --slave   /usr/bin/llvm-nm           llvm-nm          /usr/bin/llvm-nm-${version} \
    --slave   /usr/bin/llvm-objdump      llvm-objdump     /usr/bin/llvm-objdump-${version} \
    --slave   /usr/bin/llvm-profdata     llvm-profdata    /usr/bin/llvm-profdata-${version} \
    --slave   /usr/bin/llvm-ranlib       llvm-ranlib      /usr/bin/llvm-ranlib-${version} \
    --slave   /usr/bin/llvm-readobj      llvm-readobj     /usr/bin/llvm-readobj-${version} \
    --slave   /usr/bin/llvm-rtdyld       llvm-rtdyld      /usr/bin/llvm-rtdyld-${version} \
    --slave   /usr/bin/llvm-size         llvm-size        /usr/bin/llvm-size-${version} \
    --slave   /usr/bin/llvm-stress       llvm-stress      /usr/bin/llvm-stress-${version} \
    --slave   /usr/bin/llvm-symbolizer   llvm-symbolizer  /usr/bin/llvm-symbolizer-${version} \
    --slave   /usr/bin/llvm-tblgen       llvm-tblgen      /usr/bin/llvm-tblgen-${version} \
    --slave   /usr/bin/llvm-objcopy      llvm-objcopy     /usr/bin/llvm-objcopy-${version} \
    --slave   /usr/bin/llvm-strip        llvm-strip       /usr/bin/llvm-strip-${version}
                                                                                 
RUN update-alternatives \
    --verbose \
    --install /usr/bin/clang                 clang                 /usr/bin/clang-${version} ${priority} \
    --slave   /usr/bin/clang++               clang++               /usr/bin/clang++-${version}  \
    --slave   /usr/bin/asan_symbolize        asan_symbolize        /usr/bin/asan_symbolize-${version} \
    --slave   /usr/bin/clang-cpp             clang-cpp             /usr/bin/clang-cpp-${version} \
    --slave   /usr/bin/clang-check           clang-check           /usr/bin/clang-check-${version} \
    --slave   /usr/bin/clang-cl              clang-cl              /usr/bin/clang-cl-${version} \
    --slave   /usr/bin/ld.lld                ld.lld                /usr/bin/ld.lld-${version} \
    --slave   /usr/bin/lld                   lld                   /usr/bin/lld-${version} \
    --slave   /usr/bin/lld-link              lld-link              /usr/bin/lld-link-${version} \
    --slave   /usr/bin/clang-format          clang-format          /usr/bin/clang-format-${version} \
    --slave   /usr/bin/clang-format-diff     clang-format-diff     /usr/bin/clang-format-diff-${version} \
    --slave   /usr/bin/clang-include-fixer   clang-include-fixer   /usr/bin/clang-include-fixer-${version} \
    --slave   /usr/bin/clang-offload-bundler clang-offload-bundler /usr/bin/clang-offload-bundler-${version} \
    --slave   /usr/bin/clang-query           clang-query           /usr/bin/clang-query-${version} \
    --slave   /usr/bin/clang-rename          clang-rename          /usr/bin/clang-rename-${version} \
    --slave   /usr/bin/clang-reorder-fields  clang-reorder-fields  /usr/bin/clang-reorder-fields-${version} \
    --slave   /usr/bin/clang-tidy            clang-tidy            /usr/bin/clang-tidy-${version} \
    --slave   /usr/bin/lldb                  lldb                  /usr/bin/lldb-${version} \
    --slave   /usr/bin/lldb-server           lldb-server           /usr/bin/lldb-server-${version} \
    --slave   /usr/bin/clangd                clangd                /usr/bin/clangd-${version}

RUN llvm-config --version

RUN python3 -m pip install coverage toml concurrencytest psutil wllvm

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

RUN echo /usr/lib/x86_64-unknown-linux-gnu > /etc/ld.so.conf.d/libc++.conf && \
    ldconfig

RUN git clone --depth=1 https://github.com/vanhauser-thc/afl-cov /afl-cov && cd /afl-cov && \
    make install -j $(nproc) && cd .. && rm -rf afl-cov

ENV LLVM_CONFIG=llvm-config
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV AFL_SYNC_TIME=1
ENV IS_DOCKER="1"
ENV PATH=$PATH:/fuzz/sydr

ADD https://raw.githubusercontent.com/vanhauser-thc/qemu_driver/master/qemu_driver.c /opt/
ADD https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c /opt/

# Install Atheris
RUN git clone https://github.com/google/atheris && cd atheris && \
    git checkout cbf4ad989dcb4d3ef42152990ed89cfceb50e059 && \
    pip3 install . && cd .. && rm -rf atheris

# Install Go
RUN curl --silent -O https://storage.googleapis.com/golang/getgo/installer_linux && \
    chmod +x ./installer_linux && \
    SHELL="bash" ./installer_linux -version=1.22.9 && \
    rm -rf ./installer_linux

ENV GOPATH=/root/go
ENV PATH=$PATH:/root/.go/bin:$GOPATH/bin

RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest

# Install Jazzer
RUN curl -L https://github.com/bazelbuild/bazelisk/releases/download/v1.9.0/bazelisk-linux-amd64 -o /usr/local/bin/bazel && \
    chmod +x /usr/local/bin/bazel
RUN git clone https://github.com/CodeIntelligenceTesting/jazzer.git && cd jazzer && \
    git checkout d2cbfdcfc5363593f36cd972b849cc3ab070c90a && \
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

# Support files for hybrid fuzzing with LPM
ADD https://raw.githubusercontent.com/ispras/oss-sydr-fuzz/master/projects/jsoncpp/packer/packer_macro.h /opt/
ADD https://raw.githubusercontent.com/ispras/oss-sydr-fuzz/master/projects/jsoncpp/packer/main_packer.cc /opt/

# Install luajit
RUN wget https://github.com/tarantool/luajit/archive/refs/tags/v2.1.0-beta3.tar.gz
RUN  tar zxpf v2.1.0-beta3.tar.gz
WORKDIR luajit-2.1.0-beta3
RUN make && make install && ln -sf luajit-2.1.0-beta3 /usr/local/bin/luajit

# Install fresh Lua package manager version
RUN wget https://luarocks.org/releases/luarocks-3.11.1.tar.gz && tar zxpf luarocks-3.11.1.tar.gz
WORKDIR luarocks-3.11.1 
RUN ./configure && make && make install

RUN eval $(luarocks path)
RUN luarocks install cluacov

WORKDIR /

#Install luzer
RUN git clone https://github.com/azanegin/luzer.git
WORKDIR /luzer
RUN git checkout 77642ba37430eded66d171a68d7e9c3f6347d625 && luarocks build

WORKDIR /

RUN rm -rf /luzer /luarocks-3.11.1

# Install AFLplusplus
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git && cd AFLplusplus && \
    git checkout v4.30c && export CC=clang && export CXX=clang++ && \
    export LD_LIBRARY_PATH="$(llvm-config --libdir)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" && make clean && \
    PERFORMANCE=1 make distrib -j $(nproc) && make install -j $(nproc) && make clean && cd .. && rm -rf AFLplusplus
