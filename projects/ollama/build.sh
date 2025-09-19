#!/bin/bash -ex

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
    "thinking_content_fuzz:/ollama/fuzz:FuzzAddContent"
    "thinking_state_fuzz:/ollama/fuzz:FuzzParserState"
    "thinking_eat_fuzz:/ollama/fuzz:FuzzEat"
    "convert_tokenizer_fuzz:/ollama/fuzz:FuzzParseVocabularyFromTokenizer"
    "convert_vocabulary_fuzz:/ollama/fuzz:FuzzParseVocabulary"
    "model_encode_fuzz:/ollama/fuzz:FuzzEncode"
    "model_decode_fuzz:/ollama/fuzz:FuzzDecode"
    "server_manifest_fuzz:/ollama/fuzz:FuzzParseNamedManifest"
    "server_newlayer_fuzz:/ollama/fuzz:FuzzNewLayer"
)

# Sydr targets
SYDR_TARGETS=(
    "parser_parsefile_sydr:/ollama/sydr/parser"
    "thinking_content_sydr:/ollama/sydr/thinking"
    "thinking_state_sydr:/ollama/sydr/thinking"
    "thinking_eat_sydr:/ollama/sydr/thinking"
    "convert_tokenizer_sydr:/ollama/sydr/convert"
    "convert_vocabulary_sydr:/ollama/sydr/convert"
    "model_encode_sydr:/ollama/sydr/model"
    "model_decode_sydr:/ollama/sydr/model"
    "server_manifest_sydr:/ollama/sydr/server"
    "server_newlayer_sydr:/ollama/sydr/server"
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
