ARG BASE_IMAGE="sydr/ubuntu22.04-sydr-fuzz"
FROM $BASE_IMAGE

# Clone Ollama.
RUN git clone https://github.com/ollama/ollama.git /ollama

# Apply patch.
COPY ollama.patch /ollama
RUN cd /ollama && git apply ollama.patch

# Extract corpuses.
COPY corpuses.tar.gz /
RUN tar -xzf /corpuses.tar.gz -C / && mv /fuzz /corpus

# Create directories for fuzz targets.
RUN cd /ollama/cmd && mkdir -p convert model parser server thinking

# Move fuzz targets.
COPY fuzz.go /ollama

COPY convert_parsevocabulary_sydr.go /ollama/cmd/convert
COPY convert_parsevocabularyfromtokenizer_sydr.go /ollama/cmd/convert
COPY model_decode_sydr.go /ollama/cmd/model
COPY model_encode_sydr.go /ollama/cmd/model
COPY parser_parsefile_sydr.go /ollama/cmd/parser
COPY server_newlayer_sydr.go /ollama/cmd/server
COPY server_parsenamedmanifest_sydr.go /ollama/cmd/server
COPY thinking_addcontent_sydr.go /ollama/cmd/thinking
COPY thinking_eat_sydr.go /ollama/cmd/thinking
COPY thinking_parserstate_sydr.go /ollama/cmd/thinking

WORKDIR /ollama

# Build GGML
RUN mkdir -p build && cd build && \
    CC=clang-18 CXX=clang++-18 cmake --preset 'CPU' -DGGML_AVX_VNNI=OFF .. && \
    make -j

# Install go-fuzz
RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest && \
    go install github.com/dvyukov/go-fuzz/go-fuzz-build@latest
