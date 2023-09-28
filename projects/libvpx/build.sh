#!/bin/bash -ex
# Copyright 2018 Google Inc.
# Modifications copyright (C) 2023 ISP RAS
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
STANDALONE_MAIN="main.cc"

cd /libvpx

echo "[x] Libfuzzer stage"
export CC=clang
export CXX=clang++
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"


mkdir tmp
mkdir libfuzzer
pushd tmp

LDFLAGS="$CXXFLAGS" LD=$CXX /libvpx/configure \
    --enable-vp9-highbitdepth \
    --disable-unit-tests \
    --disable-examples \
    --size-limit=12288x12288 \
    --disable-webm-io \
    --enable-debug \
    --disable-vp8-encoder \
    --disable-vp9-encoder
make -j$(nproc) all
popd

fuzzer_src_name=vpx_dec_fuzzer
fuzzer_decoders=( 'vp9' 'vp8' )
for decoder in "${fuzzer_decoders[@]}"; do
  fuzzer_name=${fuzzer_src_name}"_"${decoder}

  $CXX $CXXFLAGS -std=c++11 \
    -DDECODER=${decoder} \
    -I/libvpx \
    -I/libvpx/tmp \
    -Wl,--start-group \
    -fsanitize=fuzzer \
    examples/${fuzzer_src_name}.cc -o libfuzzer/${fuzzer_name} \
    tmp/libvpx.a \
    -Wl,--end-group
done
rm -rf tmp

echo "[x] AFL++ stage"
export AFL_LLVM_DICT2FILE=/libvpx.dict
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"

mkdir tmp
mkdir afl
pushd tmp

LDFLAGS="$CXXFLAGS" LD=$CXX /libvpx/configure \
    --enable-vp9-highbitdepth \
    --disable-unit-tests \
    --disable-examples \
    --size-limit=12288x12288 \
    --disable-webm-io \
    --enable-debug \
    --disable-vp8-encoder \
    --disable-vp9-encoder
make -j$(nproc) all
popd

fuzzer_src_name=vpx_dec_fuzzer
fuzzer_decoders=( 'vp9' 'vp8' )
for decoder in "${fuzzer_decoders[@]}"; do
  fuzzer_name=${fuzzer_src_name}"_"${decoder}

  $CXX $CXXFLAGS -std=c++11 \
    -DDECODER=${decoder} \
    -I. \
    -I tmp/ \
    -Wl,--start-group \
    -fsanitize=fuzzer \
    examples/${fuzzer_src_name}.cc -o afl/${fuzzer_name} \
    tmp/libvpx.a \
    -Wl,--end-group
done

echo "[x] Cover stage"
export CC=clang
export CXX=clang++
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"

rm -rf tmp
mkdir tmp
mkdir cover
pushd tmp

LDFLAGS="$CXXFLAGS" LD=$CXX /libvpx/configure \
    --enable-vp9-highbitdepth \
    --disable-unit-tests \
    --disable-examples \
    --size-limit=12288x12288 \
    --disable-webm-io \
    --enable-debug \
    --disable-vp8-encoder \
    --disable-vp9-encoder
make -j$(nproc) all
popd

fuzzer_src_name=vpx_dec_fuzzer
fuzzer_decoders=( 'vp9' 'vp8' )
for decoder in "${fuzzer_decoders[@]}"; do
  fuzzer_name=${fuzzer_src_name}"_"${decoder}

  $CXX $CXXFLAGS -std=c++11 \
    -DDECODER=${decoder} \
    -I. \
    -I tmp/ \
    -Wl,--start-group \
    $STANDALONE_MAIN \
    examples/${fuzzer_src_name}.cc -o cover/${fuzzer_name} \
    tmp/libvpx.a \
    -lpthread \
    -Wl,--end-group
done

echo "[x] Sydr stage"
export CC=clang
export CXX=clang++
unset CFLAGS
unset CXXFLAGS

rm -rf tmp
mkdir tmp
mkdir sydr
pushd tmp

LDFLAGS="$CXXFLAGS" LD=$CXX /libvpx/configure \
    --enable-vp9-highbitdepth \
    --disable-unit-tests \
    --disable-examples \
    --size-limit=12288x12288 \
    --disable-webm-io \
    --enable-debug \
    --disable-vp8-encoder \
    --disable-vp9-encoder
make -j$(nproc) all
popd

fuzzer_src_name=vpx_dec_fuzzer
fuzzer_decoders=( 'vp9' 'vp8' )
for decoder in "${fuzzer_decoders[@]}"; do
  fuzzer_name=${fuzzer_src_name}"_"${decoder}

  $CXX $CXXFLAGS -std=c++11 \
    -DDECODER=${decoder} \
    -I. \
    -I tmp/ \
    -Wl,--start-group \
    $STANDALONE_MAIN \
    examples/${fuzzer_src_name}.cc -o sydr/${fuzzer_name} \
    tmp/libvpx.a \
    -lpthread \
    -Wl,--end-group
done

cat /vpx_dec_fuzzer.dict >> /libvpx.dict
