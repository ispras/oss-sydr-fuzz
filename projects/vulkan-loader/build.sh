#!/bin/bash -eu
# Copyright 2023 Google LLC
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

TARGET="${TARGET:-libfuzzer}"

ROOT=/vulkan-loader
BUILD_DIR="${ROOT}/build_${TARGET}"


if [[ $TARGET == "fuzzer" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
    export CXXFLAGS="$CFLAGS"
elif [[ $TARGET == "afl" ]]
then
    export CC=afl-clang-fast
    export CXX=afl-clang-fast++
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
    export CXXFLAGS="$CFLAGS"
elif [[ $TARGET == "sydr" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g"
    export CXXFLAGS="$CFLAGS"
elif [[ $TARGET == "cov" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    export CXXFLAGS="$CFLAGS"
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp /fuzz_header.h "$BUILD_DIR/fuzz_header.h"
cd "$BUILD_DIR"

cmake \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DUPDATE_DEPS=ON \
    -DCMAKE_BUILD_TYPE=Release \
    "$ROOT"

make -j"$(nproc)"

ar rcs /libvulkan.a "$BUILD_DIR"/loader/CMakeFiles/vulkan.dir/*.o

MAIN_OBJ=""
EXTRA_LINK=()

if [[ $TARGET == "sydr" || $TARGET == "cov" ]]; then
    MAIN_OBJ="/main_${TARGET}.o"
    $CC $CFLAGS -c /opt/StandaloneFuzzTargetMain.c -o "$MAIN_OBJ"
    EXTRA_LINK+=("$MAIN_OBJ")
fi
if [[ $TARGET == "fuzzer" || $TARGET == "afl" ]]; then
    export CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
    export CXXFLAGS="$CFLAGS"
fi

build_fuzzer() {
    local src="$1"
    local name="$2"

    shift 2
    local obj="/${name}_${TARGET}.o"
    local bin="/${name%_fuzzer}_${TARGET}"

    $CC $CFLAGS \
        -I/vulkan-loader/loader \
        -I/vulkan-loader/loader/generated \
        -I/vulkan-headers/include \
        "$@" \
        -c "$src" -o "$obj"

    $CXX $CXXFLAGS \
        "${EXTRA_LINK[@]}" \
        "$obj" \
        /libvulkan.a \
        -lpthread -ldl \
        -o "$bin"
}

build_fuzzer /instance_create_advanced_fuzzer.c instance_create_advanced_fuzzer -I/ -DENABLE_FILE_CALLBACK
build_fuzzer /instance_enumerate_fuzzer.c instance_enumerate_fuzzer_split_input -DSPLIT_INPUT

for fuzzer in instance_create_fuzzer json_load_fuzzer settings_fuzzer instance_enumerate_fuzzer; do
    build_fuzzer "/${fuzzer}.c" "$fuzzer"
done
