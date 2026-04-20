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

if [[ $TARGET == "fuzzer" ]]; then
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
  export CXXFLAGS="$CFLAGS -DJXL_IS_DEBUG_BUILD=1"
  LINK_FLAGS="-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
  DESTDIR="/fuzzer"
  SUFFIX=""
elif [[ $TARGET == "afl" ]]; then
  export CC=afl-clang-fast
  export CXX=afl-clang-fast++
  export CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
  export CXXFLAGS="$CFLAGS -DJXL_IS_DEBUG_BUILD=1"
  LINK_FLAGS="-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
  DESTDIR="/afl"
  SUFFIX="_afl"
elif [[ $TARGET == "sydr" ]]; then
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g"
  export CXXFLAGS=$CFLAGS
  clang -fPIE -c /opt/StandaloneFuzzTargetMain.c -o /main.o
  LINK_FLAGS="/main.o"
  DESTDIR="/sydr"
  SUFFIX="_sydr"
elif [[ $TARGET == "cov" ]]; then
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
  export CXXFLAGS="$CFLAGS -DJXL_IS_DEBUG_BUILD=1"
  clang -fPIE -c /opt/StandaloneFuzzTargetMain.c -o /main.o
  LINK_FLAGS="/main.o"
  DESTDIR="/cov"
  SUFFIX="_cov"
fi

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
  -DCXX_NO_RTTI_SUPPORTED=OFF
)

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

# Build corpus once under fuzzer target.
if [[ $TARGET == "fuzzer" ]]; then
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

    mkdir -p djxl_fuzzer_corpus
    tools/djxl_fuzzer_corpus -q -r djxl_fuzzer_corpus || true
    cp -r djxl_fuzzer_corpus /corpus_jxl

    cp -r /seed-corpora/afl-testcases/jpeg /corpus_jpeg
    rm -rf /seed-corpora
  )
  rm -rf /tmp/libjxl-corpus
fi

rm -rf /tmp/libjxl-build
mkdir -p /tmp/libjxl-build
cd /tmp/libjxl-build
cmake \
  "${build_args[@]}" \
  -DJPEGXL_FUZZER_LINK_FLAGS="${LINK_FLAGS}" \
  /libjxl

ninja clean
ninja "${fuzzers[@]}"

mkdir -p "${DESTDIR}"
for fuzzer in "${fuzzers[@]}"; do
  cp "tools/${fuzzer}" "${DESTDIR}/${fuzzer}${SUFFIX}"
done

rm -rf /tmp/libjxl-build
