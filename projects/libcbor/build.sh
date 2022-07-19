#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Build targets for libFuzzer

mkdir build
cd build
# We disable libcbor's default sanitizers since we'll be configuring them ourselves via CFLAGS.
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS=-fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero -DCMAKE_CXX_FLAGS=-fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero -D CMAKE_BUILD_TYPE=Debug -D CMAKE_INSTALL_PREFIX="install" -D CBOR_CUSTOM_ALLOC=ON -D SANITIZE=OFF ..
make "-j$(nproc)"
make install

CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
CXX="clang++"
$CXX $CXXFLAGS -std=c++11 "-Iinstall/include" \
    ../oss-fuzz/cbor_load_fuzzer.cc -o "/cbor_load_fuzzer" \
    src/libcbor.a

# Build targets for AFL++

cd ..
rm -rf build
mkdir build
cd build
# We disable libcbor's default sanitizers since we'll be configuring them ourselves via CFLAGS.
cmake -DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_CXX_COMPILER=afl-clang-fast++ -DCMAKE_CXX_FLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" -D CMAKE_BUILD_TYPE=Debug -D CMAKE_INSTALL_PREFIX="install" -D CBOR_CUSTOM_ALLOC=ON -D SANITIZE=OFF ..
make "-j$(nproc)"
make install

CXXFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
CXX="afl-clang-fast++"

$CXX $CXXFLAGS -std=c++11 -o ../oss-fuzz/afl.o -c ../oss-fuzz/afl.cc

$CXX $CXXFLAGS -std=c++11 "-Iinstall/include" \
    ../oss-fuzz/afl.o ../oss-fuzz/cbor_load_fuzzer.cc -o "/cbor_load_afl" \
    src/libcbor.a

# Build targets for Sydr

cd ..
rm -rf build
mkdir build
cd build
# We disable libcbor's default sanitizers since we'll be configuring them ourselves via CFLAGS.
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_FLAGS=-g -D CMAKE_BUILD_TYPE=Debug -D CMAKE_INSTALL_PREFIX="install" -D CBOR_CUSTOM_ALLOC=ON -D SANITIZE=OFF ..
make "-j$(nproc)"
make install

CXXFLAGS="-g"
CXX="clang++"
$CXX $CXXFLAGS -std=c++11 "-Iinstall/include" \
    ../oss-fuzz/cbor_load_sydr.cc -o "/cbor_load_sydr" \
    src/libcbor.a

# Build targets for llvm-cov

cd ..
rm -rf build
mkdir build
cd build
# We disable libcbor's default sanitizers since we'll be configuring them ourselves via CFLAGS.
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_FLAGS="-g -fprofile-instr-generate -fcoverage-mapping" -D CMAKE_BUILD_TYPE=Debug -D CMAKE_INSTALL_PREFIX="install" -D CBOR_CUSTOM_ALLOC=ON -D SANITIZE=OFF ..
make "-j$(nproc)"
make install

CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
CXX="clang++"
$CXX $CXXFLAGS -std=c++11 "-Iinstall/include" \
    ../oss-fuzz/cbor_load_sydr.cc -o "/cbor_load_cov" \
    src/libcbor.a
