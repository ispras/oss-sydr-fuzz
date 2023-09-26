#!/bin/bash -eu
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

#libFuzzer
export CC=clang
export CXX=clang++
CFLAGS="-fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero -g"
CXXFLAGS="-fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero -g"

# limit allocation size to reduce spurious OOMs
WEBP_CFLAGS="$CFLAGS -DWEBP_MAX_IMAGE_SIZE=838860800" # 800MiB

./autogen.sh
CFLAGS="$WEBP_CFLAGS" ./configure \
  --enable-asserts \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic
make clean
make -j$(nproc)

webp_libs=(
  src/demux/.libs/libwebpdemux.a
  src/mux/.libs/libwebpmux.a
  src/.libs/libwebp.a
  imageio/.libs/libimageio_util.a
  sharpyuv/.libs/libsharpyuv.a
)
webp_c_fuzzers=(
  advanced_api_fuzzer
  animation_api_fuzzer
  huffman_fuzzer
  mux_demux_api_fuzzer
  simple_api_fuzzer
)
webp_cxx_fuzzers=(
  animdecoder_fuzzer
  animencoder_fuzzer
  enc_dec_fuzzer
)
LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
for fuzzer in "${webp_c_fuzzers[@]}"; do
  $CC $CFLAGS -Isrc -I. tests/fuzzer/${fuzzer}.c -c -o tests/fuzzer/${fuzzer}.o
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    tests/fuzzer/${fuzzer}.o -o /${fuzzer} \
    "${webp_libs[@]}"
done

for fuzzer in "${webp_cxx_fuzzers[@]}"; do
  $CXX $CXXFLAGS -Isrc -I. $LIB_FUZZING_ENGINE \
    tests/fuzzer/${fuzzer}.cc -o /${fuzzer} \
    "${webp_libs[@]}"
done

for fuzzer in "${webp_c_fuzzers[@]}" "${webp_cxx_fuzzers[@]}"; do
  cp tests/fuzzer/fuzz.dict /${fuzzer}.dict
done

#AFL++
export CC=afl-clang-fast
export CXX=afl-clang-fast++

# limit allocation size to reduce spurious OOMs
WEBP_CFLAGS="$CFLAGS -DWEBP_MAX_IMAGE_SIZE=838860800" # 800MiB

CFLAGS="$WEBP_CFLAGS" ./configure \
  --enable-asserts \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic
make clean
make -j$(nproc)

webp_libs=(
  src/demux/.libs/libwebpdemux.a
  src/mux/.libs/libwebpmux.a
  src/.libs/libwebp.a
  imageio/.libs/libimageio_util.a
  sharpyuv/.libs/libsharpyuv.a
)
webp_c_fuzzers=(
  advanced_api_fuzzer
  animation_api_fuzzer
  huffman_fuzzer
  mux_demux_api_fuzzer
  simple_api_fuzzer
)
webp_cxx_fuzzers=(
  animdecoder_fuzzer
  animencoder_fuzzer
  enc_dec_fuzzer
)
LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
for fuzzer in "${webp_c_fuzzers[@]}"; do
  $CC $CFLAGS -Isrc -I. tests/fuzzer/${fuzzer}.c -c -o tests/fuzzer/${fuzzer}.o
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    tests/fuzzer/${fuzzer}.o -o /afl_${fuzzer} \
    "${webp_libs[@]}"
done

for fuzzer in "${webp_cxx_fuzzers[@]}"; do
  $CXX $CXXFLAGS -Isrc -I. $LIB_FUZZING_ENGINE \
    tests/fuzzer/${fuzzer}.cc -o /afl_${fuzzer} \
    "${webp_libs[@]}"
done

#Sydr
export CC=clang
export CXX=clang++


CFLAGS="-g"
CXXFLAGS="-g"
# limit allocation size to reduce spurious OOMs
WEBP_CFLAGS="$CFLAGS -DWEBP_MAX_IMAGE_SIZE=838860800" # 800MiB

CFLAGS="$WEBP_CFLAGS" ./configure \
  --enable-asserts \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic
make clean
make -j$(nproc)

webp_libs=(
  src/demux/.libs/libwebpdemux.a
  src/mux/.libs/libwebpmux.a
  src/.libs/libwebp.a
  imageio/.libs/libimageio_util.a
  sharpyuv/.libs/libsharpyuv.a
)
webp_c_fuzzers=(
  advanced_api_fuzzer
  animation_api_fuzzer
  huffman_fuzzer
  mux_demux_api_fuzzer
  simple_api_fuzzer
)
webp_cxx_fuzzers=(
  animdecoder_fuzzer
  animencoder_fuzzer
  enc_dec_fuzzer
)
$CC $CFLAGS main.c -c -o main.o
LIB_FUZZING_ENGINE="main.o"
for fuzzer in "${webp_c_fuzzers[@]}"; do
  $CC $CFLAGS -Isrc -I. tests/fuzzer/${fuzzer}.c -c -o tests/fuzzer/${fuzzer}.o
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -lpthread \
    tests/fuzzer/${fuzzer}.o -o /sydr_${fuzzer} \
    "${webp_libs[@]}"
done

for fuzzer in "${webp_cxx_fuzzers[@]}"; do
  $CXX $CXXFLAGS -Isrc -I. $LIB_FUZZING_ENGINE -lpthread \
    tests/fuzzer/${fuzzer}.cc -o /sydr_${fuzzer} \
    "${webp_libs[@]}"
done

#Cov

CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
# limit allocation size to reduce spurious OOMs
WEBP_CFLAGS="$CFLAGS -DWEBP_MAX_IMAGE_SIZE=838860800" # 800MiB

CFLAGS="$WEBP_CFLAGS" ./configure \
  --enable-asserts \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic
make clean
make -j$(nproc)

webp_libs=(
  src/demux/.libs/libwebpdemux.a
  src/mux/.libs/libwebpmux.a
  src/.libs/libwebp.a
  imageio/.libs/libimageio_util.a
  sharpyuv/.libs/libsharpyuv.a
)
webp_c_fuzzers=(
  advanced_api_fuzzer
  animation_api_fuzzer
  huffman_fuzzer
  mux_demux_api_fuzzer
  simple_api_fuzzer
)
webp_cxx_fuzzers=(
  animdecoder_fuzzer
  animencoder_fuzzer
  enc_dec_fuzzer
)
$CC $CFLAGS main.c -c -o main.o
LIB_FUZZING_ENGINE="main.o"
for fuzzer in "${webp_c_fuzzers[@]}"; do
  $CC $CFLAGS -Isrc -I. tests/fuzzer/${fuzzer}.c -c -o tests/fuzzer/${fuzzer}.o
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -lpthread \
    tests/fuzzer/${fuzzer}.o -o /cov_${fuzzer} \
    "${webp_libs[@]}"
done

for fuzzer in "${webp_cxx_fuzzers[@]}"; do
  $CXX $CXXFLAGS -Isrc -I. $LIB_FUZZING_ENGINE -lpthread \
    tests/fuzzer/${fuzzer}.cc -o /cov_${fuzzer} \
    "${webp_libs[@]}"
done
