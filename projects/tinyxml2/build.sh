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

CC=clang
CXX=clang++

# libFuzzer

mkdir build
cd build

cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
         -DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,undefined" \
         -DCMAKE_CXX_FLAGS="-g -fsanitize=fuzzer-no-link,address,undefined" \
         -DBUILD_SHARED_LIBS=OFF

make -j$(nproc) all

CXXFLAGS="-g -fsanitize=fuzzer,address,undefined"

$CXX $CXXFLAGS -std=c++11 -I/ /tinyxml2/fuzz.cpp -o /xmltest \
    ./libtinyxml2.a

# Sydr

cd ..
rm -rf build
mkdir build
cd build

cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
         -DCMAKE_C_FLAGS="-g" \
         -DCMAKE_CXX_FLAGS="-g" \
         -DBUILD_SHARED_LIBS=OFF

make -j$(nproc) all

CFLAGS="-g"
CXXFLAGS="-g"

$CC $CFLAGS /tinyxml2/main.c -c -o main.o

$CXX $CXXFLAGS -std=c++11 -I/ /tinyxml2/fuzz.cpp -o /xmltest_sydr \
    main.o ./libtinyxml2.a

# coverage

cd ..
rm -rf build
mkdir build
cd build

cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
         -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
         -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
         -DBUILD_SHARED_LIBS=OFF

make -j$(nproc) all

CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"

$CC $CFLAGS /tinyxml2/main.c -c -o main.o

$CXX $CXXFLAGS -std=c++11 -I/ /tinyxml2/fuzz.cpp -o /xmltest_cov \
    main.o ./libtinyxml2.a
