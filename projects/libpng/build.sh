#!/bin/bash -eu
# Copyright 2017-2018 Glenn Randers-Pehrson
# Copyright 2016 Google Inc.
# Modifications copyright (C) 2022 ISP RAS
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
# Last changed in libpng 1.6.35 [July 15, 2018]
#
# Revisions by Glenn Randers-Pehrson, 2017:
# 1. Build only the library, not the tools (changed "make -j$(nproc) all" to
#     "make -j$(nproc) libpng16.la").
# 2. Disabled WARNING and WRITE options in pnglibconf.dfa.
# 3. Build zlib alongside libpng
################################################################################

# Disable logging via library build configuration control.
cat scripts/pnglibconf.dfa | \
  sed -e "s/option STDIO/option STDIO disabled/" \
      -e "s/option WARNING /option WARNING disabled/" \
      -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
> scripts/pnglibconf.dfa.temp
mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa

# Build targets for libfuzzer

export CC=clang
export CXX=clang++
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"

autoreconf -f -i
./configure
make -j$(nproc) clean
make -j$(nproc) all

export CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

mkdir /corpus

SRC="."

# add seed corpus.
find $SRC -name "*.png" | grep -v crashers | \
     xargs -I {} cp {} /corpus


# build libpng_read_fuzzer.
$CXX $CXXFLAGS -std=c++11 -I. \
     $SRC/libpng_read_fuzzer.cc \
     -o /libpng_read_fuzzer \
     .libs/libpng16.a -lz

# Build targets for AFL++

make clean

export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"

./configure
make -j$(nproc) clean
make -j$(nproc) all

$CC $CFLAGS -I. afl.cc -c -o afl.o

$CXX $CXXFLAGS -std=c++11 -I. \
     $SRC/libpng_read_fuzzer.cc \
     -o /libpng_read_afl \
     afl.o .libs/libpng16.a -lz

# Build targets for Sydr

make clean

export CC=clang
export CXX=clang++
export CFLAGS="-g -fPIC"
export CXXFLAGS="-g -fPIC"

./configure
make -j$(nproc) clean
make -j$(nproc) all

$CC $CFLAGS -I. main.c -c -o main.o

$CXX $CXXFLAGS -std=c++11 -I. \
     $SRC/libpng_read_fuzzer.cc \
     -o /libpng_read_sydr \
     main.o .libs/libpng16.a -lz

# Build targets for llvm-cov

make clean

export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"

./configure
make -j$(nproc) clean
make -j$(nproc) all

$CC $CFLAGS -I. main.c -c -o main.o

$CXX $CXXFLAGS -std=c++11 -I. \
     $SRC/libpng_read_fuzzer.cc \
     -o /libpng_read_cov \
     main.o .libs/libpng16.a -lz
