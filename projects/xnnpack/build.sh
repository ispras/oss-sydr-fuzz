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

ROOT=/xnnpack
BUILD_DIR="${ROOT}/build_${TARGET}"

if [[ "$TARGET" == "fuzzer" ]]
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

cmake \
    -DXNNPACK_BUILD_BENCHMARKS=OFF \
    -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
    -DXNNPACK_BUILD_TESTS=ON \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    ../

make V=1 -j"$(nproc)"
cd "$ROOT"

COMMON_DEFS=(
    -DFXDIV_USE_INLINE_ASSEMBLY=0
    -DPTHREADPOOL_NO_DEPRECATED_API=1
    -DXNN_ENABLE_ARM_BF16=1
    -DXNN_ENABLE_ARM_DOTPROD=1
    -DXNN_ENABLE_ARM_FP16_SCALAR=1
    -DXNN_ENABLE_ARM_FP16_VECTOR=1
    -DXNN_ENABLE_ASSEMBLY=1
    -DXNN_ENABLE_DWCONV_MULTIPASS=0
    -DXNN_ENABLE_GEMM_M_SPECIALIZATION=1
    -DXNN_ENABLE_JIT=0
    -DXNN_ENABLE_MEMOPT=1
    -DXNN_ENABLE_RISCV_VECTOR=1
    -DXNN_ENABLE_SPARSE=1
)

COMMON_INCLUDES=(
    -I/xnnpack/src
    -I"${BUILD_DIR}/pthreadpool-source/include"
    -I"${BUILD_DIR}/FXdiv-source/include"
    -I/xnnpack/include
    -I"${BUILD_DIR}/FP16-source/include"
)

COMMON_LIBS=(
    "${BUILD_DIR}/libXNNPACK.a"
    "${BUILD_DIR}/pthreadpool/libpthreadpool.a"
    "${BUILD_DIR}/cpuinfo/libcpuinfo.a"
    "${BUILD_DIR}/libxnnpack-microkernels-all.a"
    "${BUILD_DIR}/libxnnpack-microkernels-prod.a"
)

OUT="/fuzz_model_${TARGET}"
EXTRAFLAGS=()

if [[ "$TARGET" == "fuzzer" ]]
then
    export CFLAGS="-g -fsanitize=fuzzer,address,undefined,bounds,null,float-divide-by-zero"
    export CXXFLAGS="$CFLAGS"
elif [[ "$TARGET" == "afl" || "$TARGET" == "sydr" || "$TARGET" == "cov" ]]
then
    MAIN_OBJ="/main_${TARGET}.o"
    $CC $CFLAGS -c /opt/StandaloneFuzzTargetMain.c -o "$MAIN_OBJ"
    EXTRAFLAGS+=("$MAIN_OBJ" -lpthread)
fi

$CXX $CXXFLAGS /xnnpack/fuzz_model.cc \
    "${EXTRAFLAGS[@]}" \
    "${COMMON_DEFS[@]}" \
    "${COMMON_INCLUDES[@]}" \
    "${COMMON_LIBS[@]}" \
    -o "$OUT"
