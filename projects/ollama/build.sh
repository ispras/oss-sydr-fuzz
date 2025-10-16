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

# LibFuzzer targets
LIBFUZZER_TARGETS=(
    "parser_parsefile_fuzz:/ollama/fuzz:FuzzParseFile"
    "convert_tokenizer_fuzz:/ollama/fuzz:FuzzParseVocabularyFromTokenizer"
    "convert_vocabulary_fuzz:/ollama/fuzz:FuzzParseVocabulary"
    "server_manifest_fuzz:/ollama/fuzz:FuzzParseNamedManifest"
    "harmony_parser_fuzz:/ollama/fuzz:FuzzHarmonyParser"
    "wordpiece_fuzz:/ollama/fuzz:FuzzWordPiece"
)

# Sydr targets
SYDR_TARGETS=(
    "parser_parsefile_sydr:/ollama/sydr/parser"
    "convert_tokenizer_sydr:/ollama/sydr/convert"
    "convert_vocabulary_sydr:/ollama/sydr/convert"
    "server_manifest_sydr:/ollama/sydr/server"
    "harmony_parser_sydr:/ollama/sydr/harmony"
    "wordpiece_sydr:/ollama/sydr/wordpiece"
)

build_libfuzzer() {
    local output_name="$1" pkg_dir="$2" func="$3"
    local output_path="/${output_name}"

    echo -e "Building libfuzzer target ${output_name}...\n"
    cd "$pkg_dir"
    go mod download
    go-fuzz-build -libfuzzer -o "${output_path}.a" -func "$func"
    $CC -fsanitize=fuzzer "${output_path}.a" -o "$output_path" $LDFLAGS
    rm -f "${output_path}.a"
}

build_sydr() {
    local output_name="$1" pkg_dir="$2"
    local output_path="/${output_name}"

    echo -e "Building sydr target ${output_name}...\n"
    cd "$pkg_dir"
    go build -o $output_path "${output_name}.go"
}

# Build LibFuzzer targets
for target in "${LIBFUZZER_TARGETS[@]}"; do
    IFS=':' read -r output_name pkg_dir func <<< "$target"
    build_libfuzzer "$output_name" "$pkg_dir" "$func"
done

# Build Sydr targets
for target in "${SYDR_TARGETS[@]}"; do
    IFS=':' read -r output_name pkg_dir <<< "$target"
    build_sydr "$output_name" "$pkg_dir"
done
