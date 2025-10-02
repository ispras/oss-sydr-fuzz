ARG BASE_IMAGE="sydr/ubuntu22.04-sydr-fuzz"
FROM $BASE_IMAGE

# Clone Ollama.
RUN git clone https://github.com/ollama/ollama.git /ollama

WORKDIR /ollama

RUN git checkout 05a43e078a89247dcc71c703c1bee2af97c1655d

# Apply patch.
COPY ollama.patch build.sh ./
RUN git apply ollama.patch

# Extract corpuses.
COPY corpus.zip /
RUN unzip /corpus.zip -d /

# Create directories for fuzz targets.
RUN mkdir sydr && cd sydr && mkdir -p convert parser server harmony wordpiece

# Move fuzz targets.
RUN mkdir fuzz
COPY fuzz.go fuzz

COPY server_manifest_sydr.go sydr/server
COPY parser_parsefile_sydr.go sydr/parser
COPY convert_tokenizer_sydr.go sydr/convert
COPY convert_vocabulary_sydr.go sydr/convert
COPY harmony_parser_sydr.go /ollama/sydr/harmony
COPY wordpiece_sydr.go /ollama/sydr/wordpiece

# Build GGML.
RUN mkdir -p build && cd build && \
    CC=clang-18 CXX=clang++-18 cmake --preset 'CPU' -DGGML_AVX_VNNI=OFF .. && \
    make -j

# Install go-fuzz.
RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest && \
    go install github.com/dvyukov/go-fuzz/go-fuzz-build@latest && \
    go get github.com/dvyukov/go-fuzz/go-fuzz-dep

# Build targets.
RUN ./build.sh

WORKDIR /
