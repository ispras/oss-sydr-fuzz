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
# libfuzzer
cd /node_libfuzzer

export CC=clang
export CXX=clang++
export CXXFLAGS="-g -std=c++17 -fsanitize=fuzzer-no-link,address,integer,undefined,bounds,null,float-divide-by-zero"
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,undefined,bounds,null,float-divide-by-zero"
export LDFLAGS="-latomic $CXXFLAGS"

./configure --with-ossfuzz
make -j$(nproc)
cp out/Release/*_fuzzer /

# afl
cd /node_afl

export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CXXFLAGS="-g -std=c++17 -fsanitize=address,integer,bounds,null,float-divide-by-zero"
export CFLAGS="-g -fsanitize=address,integer,bounds,null,float-divide-by-zero"
export LDFLAGS="-latomic $CXXFLAGS"

./configure --with-ossfuzz
make -j$(nproc)
cp out/Release/*_afl /

# Sydr
cd /node_sydr

export CC=clang
export CXX=clang++
export CFLAGS="-g"
export CXXFLAGS="-g -std=c++17"
export LDFLAGS="-latomic"

$CC $CFLAGS -pthread /opt/StandaloneFuzzTargetMain.c -c -o /StandaloneFuzzTargetMain.o
./configure --with-ossfuzz
make -j$(nproc)
cp out/Release/*_sydr /

# coverage
cd /node_cov

export CC=clang
export CXX=clang++
export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -std=c++17 -fprofile-instr-generate -fcoverage-mapping"
export LDFLAGS="-latomic $CXXFLAGS"

$CC $CFLAGS -pthread /opt/StandaloneFuzzTargetMain.c -c -o /StandaloneFuzzTargetMain.o
./configure --with-ossfuzz
make -j$(nproc)
cp out/Release/*_cov /
