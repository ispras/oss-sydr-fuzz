ARG BASE_IMAGE="sydr/ubuntu22.04-sydr-fuzz"
FROM $BASE_IMAGE

# Clone Ollama.
RUN git clone https://github.com/ollama/ollama.git /ollama

WORKDIR /ollama

RUN git checkout 26214125e86ac1d4512dff68c983137589cfddbf

# Apply patch.
COPY ollama.patch build.sh ./
RUN git apply ollama.patch

# Extract corpuses.
COPY corpus.zip /
RUN unzip /corpus.zip -d /

# Create directories for fuzz targets.
RUN mkdir sydr && cd sydr && mkdir -p convert model parser server thinking

# Move fuzz targets.
RUN mkdir fuzz
COPY fuzz.go fuzz

COPY thinking_state_sydr.go sydr/thinking
COPY thinking_eat_sydr.go sydr/thinking
COPY thinking_content_sydr.go sydr/thinking
COPY server_newlayer_sydr.go sydr/server
COPY server_manifest_sydr.go sydr/server
COPY parser_parsefile_sydr.go sydr/parser
COPY model_encode_sydr.go sydr/model
COPY model_decode_sydr.go sydr/model
COPY convert_tokenizer_sydr.go sydr/convert
COPY convert_vocabulary_sydr.go sydr/convert

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
