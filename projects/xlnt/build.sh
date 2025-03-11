# Copyright 2023 ISP RAS
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
cmake -DSTATIC=ON -DTESTS=OFF \
   -DCMAKE_CXX_COMPILER=clang++ \
   -DCMAKE_CXX_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
   ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

CXX="clang++"
CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /load_fuzzer ../load.cc ./source/libxlnt.a
$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /save_fuzzer ../save.cc ./source/libxlnt.a

cd .. && rm -rf build && mkdir build && cd build


# Build AFL++ targets.
cmake -DSTATIC=ON -DTESTS=OFF \
   -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
   -DCMAKE_CXX_FLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" \
   ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

CXX="afl-clang-fast++"
CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"

$CXX $CXXFLAGS -o afl.o -c ../afl.cc
$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /load_afl afl.o ../load.cc ./source/libxlnt.a
$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /save_afl afl.o ../save.cc ./source/libxlnt.a

cd .. && rm -rf build && mkdir build && cd build


# Build Honggfuzz targets.
cmake -DSTATIC=ON -DTESTS=OFF \
   -DCMAKE_CXX_COMPILER=hfuzz-clang++ \
   -DCMAKE_CXX_FLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero" \
   ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

CXX="hfuzz-clang++"
CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"

$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /load_hfuzz ../load.cc ./source/libxlnt.a
$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /save_hfuzz ../save.cc ./source/libxlnt.a

cd .. && rm -rf build && mkdir build && cd build


# Build Sydr targets.
cmake -DSTATIC=ON -DTESTS=OFF \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_CXX_FLAGS=-g \
    ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

CC="clang"
CXX="clang++"
CXXFLAGS="-g"

$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o
$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /load_sydr main.o ../load.cc ./source/libxlnt.a
$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /save_sydr main.o ../save.cc ./source/libxlnt.a

cd .. && rm -rf build && mkdir build && cd build


# Build cov targets.
cmake -DSTATIC=ON -DTESTS=OFF \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
    ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

CC="clang"
CXX="clang++"
CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
LDFLAGS="-fprofile-instr-generate"

$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o
$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /load_cov main.o ../load.cc ./source/libxlnt.a
$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o /save_cov main.o ../save.cc ./source/libxlnt.a

cd .. && rm -rf build && mkdir build && cd build
