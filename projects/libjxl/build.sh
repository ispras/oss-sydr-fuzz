#!/bin/bash -eu
# Copyright 2021 Google Inc.
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


export CXX=clang++
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined" 
export CC=clang
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined" 


build_args=(
  -G Ninja
  -DBUILD_TESTING=OFF
  -DBUILD_SHARED_LIBS=OFF
  -DJPEGXL_ENABLE_BENCHMARK=OFF
  -DJPEGXL_ENABLE_DEVTOOLS=ON
  -DJPEGXL_ENABLE_EXAMPLES=OFF
  -DJPEGXL_ENABLE_FUZZERS=ON
  -DJPEGXL_ENABLE_MANPAGES=OFF
  -DJPEGXL_ENABLE_SJPEG=OFF
  -DJPEGXL_ENABLE_VIEWERS=OFF
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON
)

# Build and generate a fuzzer corpus in release mode without instrumentation.
# This is done in a subshell since we change the environment.
(
  unset CFLAGS
  unset CXXFLAGS
  export AFL_NOOPT=1

  rm -rf /tmp/libjxl-corpus
  mkdir -p /tmp/libjxl-corpus
  cd /tmp/libjxl-corpus
  cmake "${build_args[@]}" /libjxl
  ninja clean
  ninja djxl_fuzzer_corpus


  # Generate fuzzer corpora.
  fuzzers=(
    djxl_fuzzer
  )
  for fuzzer in "${fuzzers[@]}"; do
    mkdir -p "${fuzzer}_corpus"
    "tools/${fuzzer}_corpus" -q -r "${fuzzer}_corpus" || true
  done

  for fuzzer in "${fuzzers[@]}"; do
    cp -r "${fuzzer}_corpus" "/corpus_${fuzzer}"
  done

  # Copy jxl corpus for fuzzers that expect jxl input.
  cp -r /corpus_djxl_fuzzer /corpus_transforms_fuzzer
  cp -r /corpus_djxl_fuzzer /corpus_color_encoding_fuzzer
  cp -r /corpus_djxl_fuzzer /corpus_fields_fuzzer
  cp -r /corpus_djxl_fuzzer /corpus_icc_codec_fuzzer
  cp -r /corpus_djxl_fuzzer /corpus_decode_basic_info_fuzzer
  cp -r /corpus_djxl_fuzzer /corpus_streaming_fuzzer

  # Copy jpeg corpus for cjxl_fuzzer which converts jpeg->jxl.
  cp -r /seed-corpora/afl-testcases/jpeg /corpus_cjxl_fuzzer

  # Empty corpora for fuzzers that accept any data.
  mkdir -p /corpus_rans_fuzzer
  mkdir -p /corpus_set_from_bytes_fuzzer
)

rm -rf /tmp/libjxl-corpus


# Build the fuzzers in release mode but force the inclusion of JXL_DASSERT()
# checks.
export CXXFLAGS="${CXXFLAGS} -DJXL_IS_DEBUG_BUILD=1"


build_args[${#build_args[@]}]="-DCXX_NO_RTTI_SUPPORTED=OFF"


rm -rf /tmp/libjxl-fuzzer
mkdir -p /tmp/libjxl-fuzzer
cd /tmp/libjxl-fuzzer
cmake \
  "${build_args[@]}" \
  -DJPEGXL_FUZZER_LINK_FLAGS="/usr/lib/clang/14.0.6/lib/linux/libclang_rt.fuzzer-x86_64.a" \
  /libjxl

fuzzers=(
  cjxl_fuzzer
  color_encoding_fuzzer
  decode_basic_info_fuzzer
  djxl_fuzzer
  fields_fuzzer
  icc_codec_fuzzer
  rans_fuzzer
  set_from_bytes_fuzzer
  streaming_fuzzer
  transforms_fuzzer
)

ninja clean
ninja "${fuzzers[@]}"

mkdir -p /fuzz
for fuzzer in "${fuzzers[@]}"; do
  cp "tools/${fuzzer}" /fuzz/
done

rm -rf /tmp/libjxl-fuzzer


# Build coverage targets.

export CXX=clang++
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -DJXL_IS_DEBUG_BUILD=1"
export CC=clang
export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"

clang -fPIE -c /opt/StandaloneFuzzTargetMain.c -o /main.o

rm -rf /tmp/libjxl-cov
mkdir -p /tmp/libjxl-cov
cd /tmp/libjxl-cov
cmake \
  "${build_args[@]}" \
  -DJPEGXL_FUZZER_LINK_FLAGS="/main.o" \
  /libjxl

ninja clean
ninja "${fuzzers[@]}"

mkdir -p /cov
for fuzzer in "${fuzzers[@]}"; do
  cp "tools/${fuzzer}" "/cov/${fuzzer}_cov"
done

rm -rf /tmp/libjxl-cov


# Build sydr targets.

export CXX=clang++
export CXXFLAGS="-g"
export CC=clang
export CFLAGS="-g"


rm -rf /tmp/libjxl-sydr
mkdir -p /tmp/libjxl-sydr
cd /tmp/libjxl-sydr
cmake \
  "${build_args[@]}" \
  -DJPEGXL_FUZZER_LINK_FLAGS="/main.o" \
  /libjxl

ninja clean
ninja "${fuzzers[@]}"

mkdir -p /sydr
for fuzzer in "${fuzzers[@]}"; do
  cp "tools/${fuzzer}" "/sydr/${fuzzer}_sydr"
done

rm -rf /tmp/libjxl-sydr


# Build AFL targets.
export CXX=afl-clang-fast++
export CXXFLAGS="-g -fsanitize=address,undefined -DJXL_IS_DEBUG_BUILD=1"
export CC=afl-clang-fast
export CFLAGS="-g -fsanitize=address,undefined"

rm -rf /tmp/libjxl-afl
mkdir -p /tmp/libjxl-afl
cd /tmp/libjxl-afl
cmake \
  "${build_args[@]}" \
  -DJPEGXL_FUZZER_LINK_FLAGS="-fsanitize=fuzzer" \
  /libjxl

ninja clean
ninja "${fuzzers[@]}"

mkdir -p /afl
for fuzzer in "${fuzzers[@]}"; do
  cp "tools/${fuzzer}" "/afl/${fuzzer}_afl"
done

rm -rf /tmp/libjxl-afl
