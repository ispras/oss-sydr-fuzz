#!/bin/bash -eu
# Copyright 2016 Google Inc.
# Modifications copyright (C) 2021 ISP RAS
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

# build targets for libFuzzer
./autogen.sh
./configure CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero" CC=clang CXX=clang++
make -j$(nproc) all

CC=clang
CXX=clang++
# build your fuzzer(s)
mkdir /lcms_fuzz
OUT=/lcms_fuzz
FUZZERS="cmsIT8_load_fuzzer cms_transform_fuzzer cms_overwrite_transform_fuzzer"
CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
for F in $FUZZERS; do
    $CC $CFLAGS -c -Iinclude \
        ./$F.c -o ./$F.o
    $CXX $CXXFLAGS \
        ./$F.o -o $OUT/$F \
        src/.libs/liblcms2.a
done

# build targets for AFL++
make clean
./configure CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero" CC=afl-clang-lto CXX=afl-clang-lto++
make -j$(nproc) all

CC=afl-clang-lto
CXX=afl-clang-lto++
mkdir /lcms_afl
OUT=/lcms_afl
FUZZERS="cmsIT8_load_fuzzer cms_transform_fuzzer cms_overwrite_transform_fuzzer"
CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"

$CXX $CXXFLAGS -o afl.o -c /afl.cc
for F in $FUZZERS; do
    $CC $CFLAGS -c -Iinclude \
        ./$F.c -o ./$F.o
    $CXX $CXXFLAGS \
        afl.o ./$F.o -o $OUT/$F \
        src/.libs/liblcms2.a
done

# build targets for Sydr
make clean
export CC=clang
export CXX=clang++
export CFLAGS="-g"
export CXXFLAGS="-g"
./configure
make -j$(nproc) all

# build your Sydr targets
mkdir /lcms_sydr
OUT=/lcms_sydr
FUZZERS="cmsIT8_load_sydr cms_transform_sydr cms_overwrite_transform_sydr"
for F in $FUZZERS; do
    $CC $CFLAGS -c -Iinclude \
        ./$F.c -o ./$F.o
    $CXX $CXXFLAGS \
        ./$F.o -o $OUT/$F \
        src/.libs/liblcms2.a
done

# Build targets for llvm-cov
make clean
export CC=clang
export CXX=clang++
export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
./configure
make -j$(nproc) all

# build your Sydr targets
mkdir /lcms_cov
OUT=/lcms_cov
FUZZERS="cmsIT8_load_sydr cms_transform_sydr cms_overwrite_transform_sydr"
for F in $FUZZERS; do
    $CC $CFLAGS -c -I /lcms/include \
        /lcms/$F.c -o /lcms/$F.o
    $CXX $CXXFLAGS \
        /lcms/$F.o -o $OUT/$F \
        /lcms/src/.libs/liblcms2.a
done
