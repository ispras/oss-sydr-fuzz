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
