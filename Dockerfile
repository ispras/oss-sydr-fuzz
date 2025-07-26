ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN apt-get update && \
    apt-get install -y \
    git \
    wget \
    gnupg \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Install LLVM 14 with full toolchain
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-14 main" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    clang-14 \
    lld-14 \
    libclang-rt-14-dev \
    libc++-14-dev \
    libc++abi-14-dev \
    libstdc++-10-dev && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-14 100 && \
    update-alternatives --install /usr/bin/ld ld /usr/bin/ld.lld-14 100

# Create symlinks for fuzzer libraries
RUN mkdir -p /usr/lib/llvm-14/lib/clang/14.0.6/lib/linux && \
    ln -s /usr/lib/clang/14.0.6/lib/linux/* /usr/lib/llvm-14/lib/clang/14.0.6/lib/linux/ || true

# Install CMake
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor - > /usr/share/keyrings/kitware.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/kitware.gpg] https://apt.kitware.com/ubuntu/ focal main" > /etc/apt/sources.list.d/kitware.list && \
    apt-get update && \
    apt-get install -y cmake

# Install newer Go version
RUN wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz && \
    rm go1.22.4.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin

# Clone Ollama
RUN git clone https://github.com/ollama/ollama.git /ollama && \
    cd /ollama && \
    git checkout main

# Copy project files
COPY . /ollama/

# Extract corpuses
RUN tar -xzf /ollama/corpuses.tar.gz -C /ollama/

# Recreate directory structure and move files back
RUN mkdir -p /ollama/fuzz/{convert,model,parser,server,thinking} && \
    mkdir -p /ollama/fuzz_sydr/{convert_parsevocabulary,convert_parsevocabularyfromtokenizer,model_decode,model_encode,parser_parsefile,server_newlayer,server_parsenamedmanifest,thinking_addcontent,thinking_eat,thinking_parserstate}

# Move fuzz files back to original locations
RUN mv /ollama/convert_tokenizer_fuzz.go /ollama/fuzz/convert/tokenizer_fuzz.go && \
    mv /ollama/model_sentencepiece_fuzz.go /ollama/fuzz/model/sentencepiece_fuzz.go && \
    mv /ollama/parser_parser_fuzz.go /ollama/fuzz/parser/parser_fuzz.go && \
    mv /ollama/server_layer_fuzz.go /ollama/fuzz/server/layer_fuzz.go && \
    mv /ollama/server_manifest_fuzz.go /ollama/fuzz/server/manifest_fuzz.go && \
    mv /ollama/thinking_parser_fuzz.go /ollama/fuzz/thinking/parser_fuzz.go

# Move sydr files back with existence checks
RUN mkdir -p /ollama/fuzz_sydr/convert_parsevocabulary && \
    ([ -f /ollama/convert_parsevocabulary_sydr.go ] && mv /ollama/convert_parsevocabulary_sydr.go /ollama/fuzz_sydr/convert_parsevocabulary/main.go || true) && \
    mkdir -p /ollama/fuzz_sydr/convert_parsevocabularyfromtokenizer && \
    ([ -f /ollama/convert_parsevocabularyfromtokenizer_sydr.go ] && mv /ollama/convert_parsevocabularyfromtokenizer_sydr.go /ollama/fuzz_sydr/convert_parsevocabularyfromtokenizer/main.go || true) && \
    mkdir -p /ollama/fuzz_sydr/model_decode && \
    ([ -f /ollama/model_decode_sydr.go ] && mv /ollama/model_decode_sydr.go /ollama/fuzz_sydr/model_decode/main.go || true) && \
    mkdir -p /ollama/fuzz_sydr/model_encode && \
    ([ -f /ollama/model_encode_sydr.go ] && mv /ollama/model_encode_sydr.go /ollama/fuzz_sydr/model_encode/main.go || true) && \
    mkdir -p /ollama/fuzz_sydr/parser_parsefile && \
    ([ -f /ollama/parser_parsefile_sydr.go ] && mv /ollama/parser_parsefile_sydr.go /ollama/fuzz_sydr/parser_parsefile/main.go || true) && \
    mkdir -p /ollama/fuzz_sydr/server_newlayer && \
    ([ -f /ollama/server_newlayer_sydr.go ] && mv /ollama/server_newlayer_sydr.go /ollama/fuzz_sydr/server_newlayer/main.go || true) && \
    mkdir -p /ollama/fuzz_sydr/server_parsenamedmanifest && \
    ([ -f /ollama/server_parsenamedmanifest_sydr.go ] && mv /ollama/server_parsenamedmanifest_sydr.go /ollama/fuzz_sydr/server_parsenamedmanifest/main.go || true) && \
    mkdir -p /ollama/fuzz_sydr/thinking_addcontent && \
    ([ -f /ollama/thinking_addcontent_sydr.go ] && mv /ollama/thinking_addcontent_sydr.go /ollama/fuzz_sydr/thinking_addcontent/main.go || true) && \
    mkdir -p /ollama/fuzz_sydr/thinking_eat && \
    ([ -f /ollama/thinking_eat_sydr.go ] && mv /ollama/thinking_eat_sydr.go /ollama/fuzz_sydr/thinking_eat/main.go || true) && \
    mkdir -p /ollama/fuzz_sydr/thinking_parserstate && \
    ([ -f /ollama/thinking_parserstate_sydr.go ] && mv /ollama/thinking_parserstate_sydr.go /ollama/fuzz_sydr/thinking_parserstate/main.go || true)

# Apply patch
RUN cd /ollama && git apply ollama.patch

# Make build script executable
RUN chmod +x /ollama/build.sh

WORKDIR /ollama

# Build GGML
RUN mkdir -p build && cd build && \
    CC=clang-14 CXX=clang++-14 cmake --preset 'CPU' -DGGML_AVX_VNNI=OFF .. && \
    make -j

# Set Go module mode
ENV GO111MODULE=on
RUN go mod tidy

# Install go-fuzz
RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest && \
    go install github.com/dvyukov/go-fuzz/go-fuzz-build@latest

# Create output directory
RUN mkdir -p /ollama/fuzz_binaries

CMD ["/bin/bash"]
