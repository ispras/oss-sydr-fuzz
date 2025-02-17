#!/bin/bash -eu
# Copyright (C) 2022 ISP RAS
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
cmake -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_CXX_FLAGS="-DNDEBUG -g -fsanitize=fuzzer-no-link,address,undefined" \
      ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build . --target OpenXLSX --config Release

CXX="clang++"
CXXFLAGS="-g -fsanitize=fuzzer,address,undefined"
$CXX $CXXFLAGS -std=c++17 -I/openxlsx/OpenXLSX -I./OpenXLSX \
    -I/openxlsx/OpenXLSX/external/zippy -I/openxlsx/OpenXLSX/external/nowide \
    -c /fuzzer.cc -o fuzzer.o
$CXX $CXXFLAGS ./fuzzer.o ./output/libOpenXLSX.a -o /fuzzer


# Build targets for AFL++
cd .. && rm -rf build && mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
      -DCMAKE_CXX_FLAGS="-DNDEBUG -g -fsanitize=address,undefined" \
      ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build . --target OpenXLSX --config Release

CXX="afl-clang-fast++"
CXXFLAGS="-g -fsanitize=fuzzer,address,undefined"
$CXX $CXXFLAGS -std=c++17 -I/openxlsx/OpenXLSX -I./OpenXLSX \
    -I/openxlsx/OpenXLSX/external/zippy -I/openxlsx/OpenXLSX/external/nowide \
    -c /fuzzer.cc -o fuzzer.o
$CXX $CXXFLAGS ./fuzzer.o ./output/libOpenXLSX.a -o /afl


# Build targets for Honggfuzz
cd .. && rm -rf build && mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=hfuzz-clang++ \
      -DCMAKE_CXX_FLAGS="-DNDEBUG -g -fsanitize=address,undefined" \
      ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build . --target OpenXLSX --config Release

CXX="hfuzz-clang++"
CXXFLAGS="-g -fsanitize=address,undefined"
$CXX $CXXFLAGS -std=c++17 -I/openxlsx/OpenXLSX -I./OpenXLSX \
    -I/openxlsx/OpenXLSX/external/zippy -I/openxlsx/OpenXLSX/external/nowide \
    -c /fuzzer.cc -o fuzzer.o
$CXX $CXXFLAGS ./fuzzer.o ./output/libOpenXLSX.a -o /hfuzz


# Build targets for Sydr
cd .. && rm -rf build && mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_CXX_FLAGS=-g \
      ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build . --target OpenXLSX --config Release

CXX="clang++"
CXXFLAGS="-g"
$CXX $CXXFLAGS -std=c++17 -I/openxlsx/OpenXLSX -I./OpenXLSX \
    -I/openxlsx/OpenXLSX/external/zippy -I/openxlsx/OpenXLSX/external/nowide \
    -c /sydr.cc -o sydr.o
$CXX $CXXFLAGS ./sydr.o ./output/libOpenXLSX.a -o /sydr


# Build targets for Coverage
cd .. && rm -rf build && mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_CXX_FLAGS="-g -fprofile-instr-generate -fcoverage-mapping" \
      ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build . --target OpenXLSX --config Release

CXX="clang++"
CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
$CXX $CXXFLAGS -std=c++17 -I/openxlsx/OpenXLSX -I/openxlsx/build/OpenXLSX \
    -I/openxlsx/OpenXLSX/external/zippy -I/openxlsx/OpenXLSX/external/nowide \
    -c /sydr.cc -o cov.o
$CXX $CXXFLAGS ./cov.o ./output/libOpenXLSX.a -o /cov
