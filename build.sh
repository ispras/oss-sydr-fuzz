#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Verify and setup environment
echo -e "${GREEN}Setting up environment...${NC}"

# Setup include paths
mkdir -p /usr/local/include/ggml
ln -sf /ollama/ml/backend/ggml/ggml/include/gguf.h /usr/local/include/ggml/
ln -sf /ollama/ml/backend/ggml/ggml/include/ggml.h /usr/local/include/ggml
mkdir -p /usr/local/include/amx
ln -sf /ollama/llama/llama.cpp/include/llama-cpp.h /usr/local/include/
ln -sf /ollama/llama/llama.cpp/include/llama.h /usr/local/include/
ln -sf /ollama/ml/backend/ggml/ggml/src/ggml-cpu/amx/amx.h /usr/local/include/amx/
ln -sf /ollama/ml/backend/ggml/ggml/include/ggml.h /usr/local/include/

# Set compiler and flags
export CC=clang
export CXX=clang++
export CFLAGS="-I/ollama/ml/backend/ggml/ggml/include"
export CXXFLAGS="-I/ollama/ml/backend/ggml/ggml/include"
export CGO_CFLAGS="-I/ollama/ml/backend/ggml/ggml/include"
export CGO_CXXFLAGS="-I/ollama/ml/backend/ggml/ggml/include"
export LDFLAGS="-ldl"
export CGO_LDFLAGS="-ldl"

# Install go-fuzz and dependencies
echo -e "${GREEN}Installing go-fuzz dependencies...${NC}"
go install github.com/dvyukov/go-fuzz/go-fuzz@latest
go install github.com/dvyukov/go-fuzz/go-fuzz-build@latest
go get github.com/dvyukov/go-fuzz/go-fuzz-dep

# Verify all tools are installed
export PATH="$PATH:$(go env GOPATH)/bin"
if ! command -v go-fuzz-build &> /dev/null || ! command -v go-fuzz &> /dev/null; then
    echo -e "${RED}Error: go-fuzz tools not installed properly${NC}"
    exit 1
fi

# Create symlinks for fuzzer libraries
mkdir -p /usr/lib/llvm-14/lib/clang/14.0.6/lib/linux
for lib in /usr/lib/clang/14.0.6/lib/linux/*; do
    [ -e "$lib" ] || continue
    libname=$(basename "$lib")
    ln -sf "$lib" "/usr/lib/llvm-14/lib/clang/14.0.6/lib/linux/$libname"
done

OUT_DIR="/ollama/fuzz_binaries"
mkdir -p "$OUT_DIR"
SUCCESS=0
FAILED=0

# LibFuzzer targets
LIBFUZZER_TARGETS=(
    "parser_parsefile:/ollama/fuzz/parser:parser_fuzz.go:FuzzParseFile"
    "thinking_addcontent:/ollama/fuzz/thinking:parser_fuzz.go:FuzzAddContent"
    "thinking_parserstate:/ollama/fuzz/thinking:parser_fuzz.go:FuzzParserState"
    "thinking_eat:/ollama/fuzz/thinking:parser_fuzz.go:FuzzEat"
    "convert_parsevocabularyfromtokenizer:/ollama/fuzz/convert:tokenizer_fuzz.go:FuzzParseVocabularyFromTokenizer"
    "convert_parsevocabulary:/ollama/fuzz/convert:tokenizer_fuzz.go:FuzzParseVocabulary"
    "model_encode:/ollama/fuzz/model:sentencepiece_fuzz.go:FuzzEncode"
    "model_decode:/ollama/fuzz/model:sentencepiece_fuzz.go:FuzzDecode"
    "server_parsenamedmanifest:/ollama/fuzz/server:manifest_fuzz.go:FuzzParseNamedManifest"
    "server_newlayer:/ollama/fuzz/server:layer_fuzz.go:FuzzNewLayer"
)

# Sydr targets
SYDR_TARGETS=(
    "parser_parsefile_sydr:/ollama/fuzz_sydr/parser_parsefile"
    "thinking_addcontent_sydr:/ollama/fuzz_sydr/thinking_addcontent"
    "thinking_parserstate_sydr:/ollama/fuzz_sydr/thinking_parserstate"
    "thinking_eat_sydr:/ollama/fuzz_sydr/thinking_eat"
    "convert_parsevocabularyfromtokenizer_sydr:/ollama/fuzz_sydr/convert_parsevocabularyfromtokenizer"
    "convert_parsevocabulary_sydr:/ollama/fuzz_sydr/convert_parsevocabulary"
    "model_encode_sydr:/ollama/fuzz_sydr/model_encode"
    "model_decode_sydr:/ollama/fuzz_sydr/model_decode"
    "server_parsenamedmanifest_sydr:/ollama/fuzz_sydr/server_parsenamedmanifest"
    "server_newlayer_sydr:/ollama/fuzz_sydr/server_newlayer"
)

build_libfuzzer() {
    local output_name="$1" pkg_dir="$2" go_file="$3" func="$4"
    local build_log="/tmp/${output_name}_build.log"
    local output_path="${OUT_DIR}/${output_name}"
    
    echo -n "Building libfuzzer ${output_name}... "
    
    if [ ! -d "$pkg_dir" ] || [ ! -f "${pkg_dir}/${go_file}" ]; then
        echo -e "${RED}FAILED (file/dir not found)${NC}"
        ((FAILED++))
        return 1
    fi

    (
        cd "$pkg_dir"
        if ! go mod download; then
            echo -e "${RED}Failed to download dependencies${NC}"
            return 1
        fi
        
        if ! go-fuzz-build -libfuzzer -o "${output_path}.a" -func "$func" > "$build_log" 2>&1; then
            return 1
        fi
        
        if ! clang -fsanitize=fuzzer "${output_path}.a" -o "$output_path" \
            $LDFLAGS $CGO_LDFLAGS >> "$build_log" 2>&1; then
            return 1
        fi
    )

    if [ $? -ne 0 ] || [ ! -f "$output_path" ]; then
        echo -e "${RED}FAILED${NC}"
        cat "$build_log"
        ((FAILED++))
        rm -f "${output_path}.a"
        return 1
    fi
    
    echo -e "${GREEN}OK${NC} → ${output_path}"
    ((SUCCESS++))
    rm -f "${output_path}.a"
}

build_sydr() {
    local output_name="$1" pkg_dir="$2"
    local build_log="/tmp/${output_name}_build.log"
    local output_path="${OUT_DIR}/${output_name}"
    
    echo -n "Building sydr ${output_name}... "
    
    if [ ! -d "$pkg_dir" ]; then
        echo -e "${RED}FAILED (dir not found)${NC}"
        ((FAILED++))
        return 1
    fi

    (
        cd "$pkg_dir"
        if ! go build -tags=gofuzz -o "$output_path" > "$build_log" 2>&1; then
            return 1
        fi
    )

    if [ $? -ne 0 ] || [ ! -f "$output_path" ]; then
        echo -e "${RED}FAILED${NC}"
        cat "$build_log"
        ((FAILED++))
        return 1
    fi
    
    echo -e "${GREEN}OK${NC} → ${output_path}"
    ((SUCCESS++))
}

# Main build process
echo -e "${GREEN}Starting build process...${NC}"

# Print environment for debugging
echo -e "\n${GREEN}Environment variables:${NC}"
echo "CC=$CC"
echo "CXX=$CXX"
echo "CFLAGS=$CFLAGS"
echo "CXXFLAGS=$CXXFLAGS"
echo "CGO_CFLAGS=$CGO_CFLAGS"
echo "CGO_CXXFLAGS=$CGO_CXXFLAGS"
echo "LDFLAGS=$LDFLAGS"
echo "CGO_LDFLAGS=$CGO_LDFLAGS"

# Build LibFuzzer targets
echo -e "\n${GREEN}Building LibFuzzer targets:${NC}"
for target in "${LIBFUZZER_TARGETS[@]}"; do
    IFS=':' read -r output_name pkg_dir go_file func <<< "$target"
    build_libfuzzer "$output_name" "$pkg_dir" "$go_file" "$func"
done

# Build Sydr targets
echo -e "\n${GREEN}Building Sydr targets:${NC}"
for target in "${SYDR_TARGETS[@]}"; do
    IFS=':' read -r output_name pkg_dir <<< "$target"
    build_sydr "$output_name" "$pkg_dir"
done

# Summary
TOTAL_TARGETS=$((${#LIBFUZZER_TARGETS[@]} + ${#SYDR_TARGETS[@]}))
echo -e "\n${GREEN}Build summary:${NC}"
echo -e "${GREEN}Successfully built: $SUCCESS${NC}"
echo -e "${RED}Failed to build: $FAILED${NC}"
echo -e "Total targets: $TOTAL_TARGETS"

if [ "$FAILED" -gt 0 ]; then
    echo -e "${RED}Some targets failed to build. Check logs above for details.${NC}"
    exit 1
else
    echo -e "${GREEN}All targets built successfully!${NC}"
    echo -e "Fuzz binaries are available in ${OUT_DIR}"
    exit 0
fi
