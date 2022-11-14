#!/bin/bash -eu
# Copyright 2016 Google Inc.
# Modifications copyright (C) 2022 ISP RAS
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

# Build targets for libfuzzer

export CC=clang
export CXX=clang++
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"

./configure
make -j$(nproc) clean
make -j$(nproc) all


export CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

mkdir /corpus

cp *.* /corpus

SRC="."

for f in $(find $SRC -name '*_fuzzer.cc'); do
    b=$(basename -s .cc $f)
    $CXX $CXXFLAGS -std=c++11 -I. $f -o /$b ./libz.a
done

for f in $(find $SRC -name '*_fuzzer.c'); do
    b=$(basename -s .c $f)
    $CC $CFLAGS -I. $f -c -o /tmp/$b.o
    $CXX $CXXFLAGS -o /$b /tmp/$b.o ./libz.a
    rm -f /tmp/$b.o=
done

# Build targets for AFL++

make clean

export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"

./configure
make -j$(nproc) clean
make -j$(nproc) all

SRC="."

$CC $CFLAGS -I. afl.cc -c -o afl.o

for f in $(find $SRC -name '*_fuzzer.cc'); do
    b=$(basename -s .cc $f)_afl
    $CXX $CXXFLAGS -std=c++11 -I. $f -o /$b afl.o ./libz.a
done

for f in $(find $SRC -name '*_fuzzer.c'); do
    b=$(basename -s .c $f)_afl
    $CC $CFLAGS -I. $f -c -o /tmp/$b.o
    $CXX $CXXFLAGS -o /$b afl.o /tmp/$b.o ./libz.a
    rm -f /tmp/$b.o=
done

# Build targets for Sydr

make clean

export CC=clang
export CXX=clang++
export CFLAGS="-g -fPIC"
export CXXFLAGS="-g -fPIC"

./configure
make -j$(nproc) clean
make -j$(nproc) all

SRC="."

$CC $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o

for f in $(find $SRC -name '*_fuzzer.cc'); do
    b=$(basename -s .cc $f)_sydr
    $CXX $CXXFLAGS -std=c++11 -I. $f -o /$b main.o ./libz.a
done

for f in $(find $SRC -name '*_fuzzer.c'); do
    b=$(basename -s .c $f)_sydr
    $CC $CFLAGS -I. $f -c -o /tmp/$b.o
    $CXX $CXXFLAGS -o /$b /tmp/$b.o main.o ./libz.a
    rm -f /tmp/$b.o=
done

# Build targets for llvm-cov

make clean

export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"

./configure
make -j$(nproc) clean
make -j$(nproc) all

SRC="."

$CC $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o

for f in $(find $SRC -name '*_fuzzer.cc'); do
    b=$(basename -s .cc $f)_cov
    $CXX $CXXFLAGS -std=c++11 -I. $f -o /$b main.o ./libz.a
done

for f in $(find $SRC -name '*_fuzzer.c'); do
    b=$(basename -s .c $f)_cov
    $CC $CFLAGS -I. $f -c -o /tmp/$b.o
    $CXX $CXXFLAGS -o /$b /tmp/$b.o main.o ./libz.a
    rm -f /tmp/$b.o=
done
