#!/bin/bash -ex
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

# Set compiler and flags
export CC=clang-18
export CXX=clang++-18
export CFLAGS="-I/ollama/ml/backend/ggml/ggml/include -I/ollama/llama/llama.cpp/vendor -I/ollama/llama/llama.cpp/include -I/ollama/ml/backend/ggml/ggml/src/ggml-cpu"
export CXXFLAGS=$CFLAGS
export CGO_CFLAGS=$CFLAGS
export CGO_CXXFLAGS=$CFLAGS
export LDFLAGS="-ldl"
export CGO_LDFLAGS="-ldl"

# Build libFuzzer
cd /ollama/fuzz
go mod download

go-fuzz-build -libfuzzer -o parsefile.a -func FuzzParseFile
$CC -fsanitize=fuzzer parsefile.a -o /parser_parsefile_fuzz $LDFLAGS

go-fuzz-build -libfuzzer -o tokenizer.a -func FuzzParseVocabularyFromTokenizer
$CC -fsanitize=fuzzer tokenizer.a -o /convert_tokenizer_fuzz $LDFLAGS

go-fuzz-build -libfuzzer -o vocabulary.a -func FuzzParseVocabulary
$CC -fsanitize=fuzzer vocabulary.a -o /convert_vocabulary_fuzz $LDFLAGS

go-fuzz-build -libfuzzer -o manifest.a -func FuzzParseNamedManifest
$CC -fsanitize=fuzzer manifest.a -o /server_manifest_fuzz $LDFLAGS

go-fuzz-build -libfuzzer -o harmony.a -func FuzzHarmonyParser
$CC -fsanitize=fuzzer harmony.a -o /harmony_parser_fuzz $LDFLAGS

go-fuzz-build -libfuzzer -o wordpiece.a -func FuzzWordPiece
$CC -fsanitize=fuzzer wordpiece.a -o /wordpiece_fuzz $LDFLAGS

rm -f *.a
cd ..

# Build Sydr
cd /ollama/sydr/parser/parsefile
go build -o /parser_parsefile_sydr

cd /ollama/sydr/convert/tokenizer
go build -o /convert_tokenizer_sydr

cd /ollama/sydr/convert/vocabulary
go build -o /convert_vocabulary_sydr

cd /ollama/sydr/server/manifest
go build -o /server_manifest_sydr

cd /ollama/sydr/harmony/parser
go build -o /harmony_parser_sydr

cd /ollama/sydr/wordpiece/encode
go build -o /wordpiece_sydr

# Build coverage
cd /ollama
go build -cover -covermode=atomic -coverpkg=./... -o /parser_parsefile_cov sydr/parser/parsefile/main.go
go build -cover -covermode=atomic -coverpkg=./... -o /convert_tokenizer_cov sydr/convert/tokenizer/main.go
go build -cover -covermode=atomic -coverpkg=./... -o /convert_vocabulary_cov sydr/convert/vocabulary/main.go
go build -cover -covermode=atomic -coverpkg=./... -o /server_manifest_cov sydr/server/manifest/main.go
go build -cover -covermode=atomic -coverpkg=./... -o /harmony_parser_cov sydr/harmony/parser/main.go
go build -cover -covermode=atomic -coverpkg=./... -o /wordpiece_cov sydr/wordpiece/encode/main.go
