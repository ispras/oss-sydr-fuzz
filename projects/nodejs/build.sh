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
# afl
cd /node_afl

export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CXXFLAGS="-fsanitize=address,integer,bounds,null,float-divide-by-zero"
export CFLAGS=$CXXFLAGS
export LDFLAGS="-latomic $CXXFLAGS"

./configure
make -j$(nproc)
ar -rcT static.a $(find . -name "*.o")
$CXX $CXXFLAGS -pthread v8_compile.cpp -o /v8_compile_afl -I./deps/v8/include -I./deps/v8/include/libplatform ./static.a -ldl

# Sydr
cd ..
cd /node_sydr

export CC=clang
export CXX=clang++
export CFLAGS="-g"
export CXXFLAGS="-g"
export LDFLAGS="-latomic"

./configure
make -j$(nproc)
ar -rcT static.a $(find . -name "*.o")
$CXX $CXXFLAGS -pthread v8_compile_sydr.cpp -o /v8_compile_sydr \
    -I./deps/v8/include -I./deps/v8/include/libplatform  ./static.a -ldl

# coverage
cd ..
cd /node_cov

export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export LDFLAGS="-latomic $CXXFLAGS"

./configure
make -j$(nproc)
ar -rcT static.a $(find . -name "*.o")
$CXX $CXXFLAGS -pthread v8_compile_sydr.cpp -o /v8_compile_cov \
   -I./deps/v8/include -I./deps/v8/include/libplatform ./static.a -ldl
