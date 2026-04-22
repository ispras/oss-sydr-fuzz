#!/bin/bash -eu
# Copyright 2016 Google Inc.
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
###########################################################################

BUILD_DIR="/brotli/build_${TARGET}"

if [[ "$TARGET" == "libfuzzer" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined,bounds,null,float-divide-by-zero"
    export CXXFLAGS="$CFLAGS"
elif [[ "$TARGET" == "afl" ]]
then
    export CC=afl-clang-fast
    export CXX=afl-clang-fast++
    export CFLAGS="-g -fsanitize=address,undefined,bounds,null,float-divide-by-zero"
    export CXXFLAGS="$CFLAGS"
elif [[ "$TARGET" == "sydr" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g"
    export CXXFLAGS="$CFLAGS"
elif [[ "$TARGET" == "cov" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    export CXXFLAGS="$CFLAGS"
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake /brotli -DBUILD_TESTING=ON -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS"
make -j$(nproc)
cd /brotli

OUT="/decode_${TARGET}"
EXTRAFLAGS=()

if [[ "$TARGET" == "libfuzzer" || "$TARGET" == "afl" ]]
then
    export CFLAGS="-g -fsanitize=fuzzer,address,undefined,bounds,null,float-divide-by-zero"
    export CXXFLAGS="$CFLAGS"
elif [[ "$TARGET" == "sydr" || "$TARGET" == "cov" ]]
then
    MAIN_OBJ="/main_${TARGET}.o"
    $CC $CFLAGS -c /opt/StandaloneFuzzTargetMain.c -o "$MAIN_OBJ"
    EXTRAFLAGS+=("$MAIN_OBJ")
fi

$CC $CFLAGS -c -std=c99 -I. -I./c/include c/fuzz/decode_fuzzer.c
$CXX $CXXFLAGS ./decode_fuzzer.o \
    "${EXTRAFLAGS[@]}" \
    "${BUILD_DIR}/libbrotlidec.a" \
    "${BUILD_DIR}/libbrotlicommon.a" \
    -o "$OUT"
