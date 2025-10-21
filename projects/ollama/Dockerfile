# Copyright 2025 ISP RAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

ARG BASE_IMAGE="sydr/ubuntu22.04-sydr-fuzz"
FROM $BASE_IMAGE

# Clone Ollama.
RUN git clone https://github.com/ollama/ollama.git /ollama

WORKDIR /ollama

RUN git checkout 05a43e078a89247dcc71c703c1bee2af97c1655d

RUN sed -i '270ipanic("reached TP")' /ollama/convert/tokenizer.go
RUN sed -i '273ipanic("reached TP")' /ollama/convert/tokenizer.go
RUN sed -i '276ipanic("reached TP")' /ollama/convert/tokenizer.go
RUN sed -i '300ipanic("reached TP")' /ollama/convert/tokenizer.go

RUN sed -i '47ipanic("reached TP")' /ollama/convert/tokenizer_spm.go
RUN sed -i '50ipanic("reached TP")' /ollama/convert/tokenizer_spm.go
RUN sed -i '96ipanic("reached TP")' /ollama/convert/tokenizer_spm.go

RUN sed -i '106ipanic("reached TP")' /ollama/harmony/harmonyparser.go
RUN sed -i '213ipanic("reached TP")' /ollama/harmony/harmonyparser.go
RUN sed -i '223ipanic("reached TP")' /ollama/harmony/harmonyparser.go
RUN sed -i '231ipanic("reached TP")' /ollama/harmony/harmonyparser.go

RUN sed -i '396ipanic("reached TP")' /ollama/parser/parser.go
RUN sed -i '407ipanic("reached TP")' /ollama/parser/parser.go
RUN sed -i '432ipanic("reached TP")' /ollama/parser/parser.go
RUN sed -i '444ipanic("reached TP")' /ollama/parser/parser.go
RUN sed -i '479ipanic("reached TP")' /ollama/parser/parser.go

RUN sed -i '89ipanic("reached TP")' /ollama/server/manifest.go
RUN sed -i '95ipanic("reached TP")' /ollama/server/manifest.go

RUN sed -i '144ipanic("reached TP")' /ollama/model/wordpiece.go

RUN sed -i '80ipanic("reached TP")' /ollama/model/vocabulary.go

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
