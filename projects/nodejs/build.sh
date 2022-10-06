#!/bin/bash
# Copyright 2017 Google Inc.
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
################################################################################

export CC=clang
export CXX=clang++

# libFuzzer
cd /node_libfuzzer

./configure

CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
CFLAGS=$CXXFLAGS
LDFLAGS="-latomic $CXXFLAGS"
CXXFLAGS=$CXXFLAGS CFLAGS=$CFLAGS LDFLAGS=$LDFLAGS make -j$(nproc) all

ar -rcT static.a $(find . -name "*.o")

$CXX $CXXFLAGS -pthread v8_compile.cpp -o /v8_compile \
    -I./deps/v8/include -I./deps/v8/include/libplatform ./static.a

# Sydr
cd ..
cd /node_sydr

CFLAGS="-g"
CXXFLAGS="-g"

CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS make -j$(nproc) all

$CC $CFLAGS /node/main.c -c -o main.o

ar -rcT static.a $(find . -name "*.o")

$CXX $CXXFLAGS -pthread v8_compile.cpp -o /v8_compile_sydr \
    -I./deps/v8/include -I./deps/v8/include/libplatform main.o ./static.a

# coverage
cd ..
cd /node_cov

CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"

CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS  make -j$(nproc) all

ar -rcT static.a $(find . -name "*.o")

$CC $CFLAGS /node/main.c -c -o main.o

$CXX $CXXFLAGS -pthread v8_compile.cpp -o /v8_compile_cov \
    -I./deps/v8/include -I./deps/v8/include/libplatform main.o ./static.a


