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

export AFL_LLVM_ALLOWLIST=/libwebp.list
# limit allocation size to reduce spurious OOMs
export WEBP_CFLAGS="-DWEBP_MAX_IMAGE_SIZE=838860800" # 800MiB

for i in cmplog compcov ctx ngram asan; do
    cp -r libwebp libwebp-$i
done


# Sydr
cd libwebp
./autogen.sh
CC=clang CFLAGS="-g $WEBP_CFLAGS" ./configure \
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

# Cmplog
cd ../libwebp-cmplog
git apply vhtc.patch
./autogen.sh
CC=clang CFLAGS="$WEBP_CFLAGS" ./configure \
  --enable-asserts \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic
make clean
make CC=afl-clang-fast AFL_LLVM_CMPLOG=1 -j$(nproc)

# Asan
cd ../libwebp-asan
git apply vhtc.patch
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
make CC=afl-clang-fast AFL_USE_ASAN=1 -j$(nproc)

# LAF
cd ../libwebp-compcov
git apply vhtc.patch
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
make CC=afl-clang-fast AFL_LLVM_LAF_ALL=1 -j$(nproc)

# CTX
cd ../libwebp-ctx
git apply vhtc.patch
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
make CC=afl-clang-fast AFL_LLVM_INSTRUMENT=CTX -j$(nproc)

# NGRAM-8
cd ../libwebp-ngram
git apply vhtc.patch
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
make CC=afl-clang-fast AFL_LLVM_INSTRUMENT=NGRAM-8 -j$(nproc)
