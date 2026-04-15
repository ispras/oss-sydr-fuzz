#!/bin/bash -eu
# Copyright 2024 Google LLC
# Modifications copyright (C) 2026 ISP RAS
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


set -e

cd /llama.cpp

# Clean previous build
rm -rf build *.o

echo "Build directory clean"

# Set build flags.
ENGINE="/StandaloneFuzzTargetMain.o"

export GGML_NO_OPENMP=1
export GGML_STATIC=1

# Avoid function that forks + starts instance of gdb.
sed -i 's/ggml_print_backtrace();//g' ./ggml/src/ggml.c

# Remove statefulness during fuzzing.
sed -i 's/static bool is_first_call/bool is_first_call/g' ./ggml/src/ggml.c

# Patch callocs to avoid allocating large chunks.
sed -i 's/ggml_calloc(size_t num, size_t size) {/ggml_calloc(size_t num, size_t size) {\nif ((num * size) > 9000000) {GGML_ABORT("calloc err");}\n/g' -i ./ggml/src/ggml.c

# Patch a potentially unbounded loop that causes timeouts
sed -i 's/ok = ok \&\& (info->n_dims <= GGML_MAX_DIMS);/ok = ok \&\& (info->n_dims <= GGML_MAX_DIMS);\nif (!ok) {fclose(file); gguf_free(ctx); return NULL;}/g' ./ggml/src/ggml.c

rm -rf $OUT
mkdir -p $OUT

# For non-libafl target we can build libs only once.
if [[ "$TARGET" != "libafl" ]]
then
    cmake -B build -DLLAMA_CURL=OFF  -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DBUILD_SHARED_LIBS=OFF -DLLAMA_BUILD_SERVER=OFF
    cmake --build build --config Debug -j16
    $CC $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o /StandaloneFuzzTargetMain.o
fi

# Convert models into header files so we can use them for fuzzing.
xxd -i models/ggml-vocab-bert-bge.gguf > model_header_bge.h
xxd -i models/ggml-vocab-llama-bpe.gguf > model_header_bpe.h
xxd -i models/ggml-vocab-llama-spm.gguf > model_header_spm.h
xxd -i models/ggml-vocab-qwen2.gguf > model_header_qwen2.h
xxd -i models/ggml-vocab-command-r.gguf > model_header_command_r.h
xxd -i models/ggml-vocab-aquila.gguf > model_header_aquila.h
xxd -i models/ggml-vocab-gpt-2.gguf > model_header_gpt_2.h
xxd -i models/ggml-vocab-baichuan.gguf > model_header_baichuan.h
xxd -i models/ggml-vocab-deepseek-coder.gguf > model_header_deepseek_coder.h
xxd -i models/ggml-vocab-falcon.gguf > model_header_falcon.h

mkdir ./build/myos
find ./build/ggml/ -name *.o -exec cp {} ./build/myos/ \;
find ./build/src/ -name *.o -exec cp {} ./build/myos/ \;
find ./build/common/ -name *.o -exec cp {} ./build/myos/ \;

OBJ_FILES="/llama.cpp/build/myos/*.o"
FLAGS="-std=c++17 -Iggml/include -Iggml/src -Iinclude -Isrc -Icommon -Ivendor -I./ -DNDEBUG -DGGML_USE_LLAMAFILE"
LIB_FUZZING_ENGINE=$ENGINE

# Build targets
build_target(){
    target=$1
    echo "=========== Build target ${target}_$TARGET ==========="

    if [[ "$TARGET" == "libafl" ]]
    then
        export LIBAFL_SHARED_NAME="llama_${target}"
        cmake -B build -DLLAMA_CURL=OFF -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DBUILD_SHARED_LIBS=OFF -DLLAMA_BUILD_SERVER=OFF
        cmake --build build --config Debug -j16
        $CC $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o /StandaloneFuzzTargetMain.o
    fi

    # Build target
    $CXX $CXXFLAGS ${FLAGS} fuzzers/$target.cpp -c -o ./$target.o
    $CXX $CXXFLAGS ${FLAGS} ./$target.o \
        -Wl,--whole-archive,"/llama.cpp/build/src/libllama.a" -Wl,--no-whole-archive \
        -WL,--whole-archive,"/llama.cpp/build/ggml/src/libggml-cpu.a" -Wl,--no-whole-archive \
        -ldl -pthread -lm -lrt /llama.cpp/build/ggml/src/libggml-cpu.a ./build/ggml/src/libggml-base.a \
        ./build/ggml/src/libggml.a ./build/common/libcommon.a \
        /llama.cpp/build/ggml/src/libggml-cpu.a $LIB_FUZZING_ENGINE \
        -o $OUT/${target}_$TARGET
}

targets=("fuzz_grammar" "fuzz_load_model" "fuzz_inference" "fuzz_structured" "fuzz_structurally_created" "fuzz_json_to_grammar" "fuzz_apply_template")
for fuzztarget in ${targets[@]}; do
    build_target $fuzztarget &
done

wait

# Build fuzz_tokenizer target with different flags
build_tokenizer(){
    flag=$1
    target="$(echo ${flag,,})"
    echo "=========== Build target fuzz_tokenizer_${target}_$TARGET ==========="

    if [[ "$TARGET" == "libafl" ]]
    then
        export LIBAFL_SHARED_NAME="llama_${target}"
        cmake -B build -DLLAMA_CURL=OFF -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DBUILD_SHARED_LIBS=OFF -DLLAMA_BUILD_SERVER=OFF
        cmake --build build --config Debug -j16
        $CC $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o /StandaloneFuzzTargetMain.o
    fi

    # Build target
    $CXX $CXXFLAGS ${FLAGS} fuzzers/fuzz_tokenizer.cpp -c -o ./fuzz_tokenizer_${target}.o
    $CXX $CXXFLAGS ${FLAGS} -DFUZZ_$flag ./fuzz_tokenizer_$target.o \
        -Wl,--whole-archive,"/llama.cpp/build/src/libllama.a" -Wl,--no-whole-archive \
        -WL,--whole-archive,"/llama.cpp/build/ggml/src/libggml-cpu.a" -Wl,--no-whole-archive \
        -ldl -pthread -lm -lrt /llama.cpp/build/ggml/src/libggml-cpu.a ./build/ggml/src/libggml-base.a \
        ./build/common/libcommon.a ./build/ggml/src/libggml.a ./build/common/libcommon.a \
        /llama.cpp/build/ggml/src/libggml-cpu.a $LIB_FUZZING_ENGINE \
        -o $OUT/fuzz_tokenizer_${target}_$TARGET
}

token_flags=("BGE" "BPE" "SPM" "COMMAND_R" "AQUILA" "QWEN2" "GPT_2" "BAICHUAN" "DEEPSEEK_CODER" "FALCON")
for fuzztarget in ${token_flags[@]}; do
    build_tokenizer $fuzztarget &
done

wait
