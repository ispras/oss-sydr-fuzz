# Copyright 2021 ISP RAS
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

#!/bin/bash -eu

# Build libFuzzer targets.
mkdir build
cd build
cmake -D STATIC=ON -D TESTS=OFF \
   -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_CXX_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
     ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

CXX="clang++"
CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o load_fuzzer.o -c ../load_fuzzer.cc

$CXX $CXXFLAGS load_fuzzer.o ./source/libxlnt.a  -o /load_fuzzer

cd .. && rm -rf build && mkdir build && cd build

# Build AFL++ targets.
cmake -D STATIC=ON -D TESTS=OFF \
   -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
    -DCMAKE_CXX_FLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" \
     ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

CXX="afl-clang-fast++"
CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"

$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o load_fuzzer.o -c ../load_fuzzer.cc

$CXX $CXXFLAGS -o afl.o -c ../afl.cc

$CXX $CXXFLAGS afl.o load_fuzzer.o ./source/libxlnt.a  -o /load_afl

cd .. && rm -rf build && mkdir build && cd build

# Build Sydr targets.
cmake -DSTATIC=ON -D TESTS=OFF \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_CXX_FLAGS=-g \
    ..

CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

CXX="clang++"
CXXFLAGS="-g"

$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o load_sydr.o -c ../load_sydr.cc

$CXX $CXXFLAGS load_sydr.o ./source/libxlnt.a  -o /load_sydr

# Build cov targets.
cmake -DSTATIC=ON -D TESTS=OFF \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
    ..

CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

CXX="clang++"
CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
LDFLAGS="-fprofile-instr-generate"

$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o load_cov.o -c ../load_sydr.cc

$CXX $CXXFLAGS load_cov.o ./source/libxlnt.a  -o /load_cov
