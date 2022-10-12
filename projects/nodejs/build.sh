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
CC=afl-clang-fast
CXX=afl-clang-fast++

# afl
cd /node_afl

CXXFLAGS="-fsanitize=address,integer,bounds,null,float-divide-by-zero"
CFLAGS=$CXXFLAGS
LDFLAGS="-latomic $CXXFLAGS"

./configure
CC=$CC CXX=$CXX CXXFLAGS=$CXXFLAGS CFLAGS=$CFLAGS LDFLAGS=$LDFLAGS make -j$(nproc)

ar -rcT static.a $(find . -name "*.o")

$CXX $CXXFLAGS -pthread v8_compile.cpp  -o ./v8_compile_afl -I./deps/v8/include -I./deps/v8/include/libplatform ./static.a -ldl

# Sydr
cd ..
cd /node_sydr

CC=clang
CXX=clang++
CFLAGS="-g"
CXXFLAGS="-g"
LDFLAGS="-latomic"

./configure
CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS LDFLAGS=$LDFLAGS make -j$(nproc)

ar -rcT static.a $(find . -name "*.o")
$CXX $CXXFLAGS -pthread v8_compile_sydr.cpp -o /v8_compile_sydr \
    -I./deps/v8/include -I./deps/v8/include/libplatform  ./static.a -ldl
# coverage
cd ..
cd /node_cov

CC=clang
CXX=clang++
CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
LDFLAGS="-latomic $CXXFLAGS"

./configure
CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS LDFLAGS=$LDFLAGS  make -j$(nproc)


ar -rcT static.a $(find . -name "*.o")

$CXX $CXXFLAGS -pthread v8_compile_sydr.cpp -o /v8_compile_cov \
   -I./deps/v8/include -I./deps/v8/include/libplatform ./static.a -ldl


