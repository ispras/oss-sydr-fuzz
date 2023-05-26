#!/bin/bash -eu
# Copyright 2023 Google LLC.
# Modifications copyright (C) 2023 ISP RAS
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

# build target for libFuzzer

export CC=clang
export CXX=clang++
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export LDFLAGS="$CFLAGS"

mkdir build-dir && cd build-dir
cmake -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_BUILD_TYPE:STRING=Release \
    -DBUILD_SHARED_LIBS:BOOL=OFF \
    -DBUILD_TESTING:BOOL=OFF \
    -DCMAKE_VERBOSE_MAKEFILES:BOOL=ON \
    -DHDF5_BUILD_EXAMPLES:BOOL=OFF \
    -DHDF5_BUILD_TOOLS:BOOL=OFF \
    -DHDF5_ENABLE_SANITIZERS:BOOL=ON \
    -DHDF5_ENABLE_Z_LIB_SUPPORT:BOOL=ON \
    ..

# Make the build verbose for easy logging inspection
cmake --build . --verbose --config Release -j$(nproc)
cd ..

export CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export LDFLAGS="$CFLAGS"

$CC $CFLAGS -std=c99 -I./src -I./build-dir/src -I./src/H5FDsubfiling/ \
    /h5_read_fuzzer.c ./build-dir/bin/libhdf5.a  -lz -o /h5_read_fuzzer

# build target for Sydr

export CC=clang
export CXX=clang++
export CFLAGS="-g"
export CXXFLAGS="-g"
export LDFLAGS="$CFLAGS"

rm -rf build-dir && mkdir build-dir && cd build-dir
cmake -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_BUILD_TYPE:STRING=Release \
    -DBUILD_SHARED_LIBS:BOOL=OFF \
    -DBUILD_TESTING:BOOL=OFF \
    -DCMAKE_VERBOSE_MAKEFILES:BOOL=ON \
    -DHDF5_BUILD_EXAMPLES:BOOL=OFF \
    -DHDF5_BUILD_TOOLS:BOOL=OFF \
    -DHDF5_ENABLE_SANITIZERS:BOOL=ON \
    -DHDF5_ENABLE_Z_LIB_SUPPORT:BOOL=ON \
    ..

# Make the build verbose for easy logging inspection
cmake --build . --verbose --config Release -j$(nproc)
cd ..

$CC $CFLAGS -pthread /opt/StandaloneFuzzTargetMain.c -c -o /StandaloneFuzzTargetMain.o

$CC $CFLAGS -std=c99 -I./src -I./build-dir/src -I./src/H5FDsubfiling/ \
    /StandaloneFuzzTargetMain.o /h5_read_fuzzer.c ./build-dir/bin/libhdf5.a -ldl -lm -lz -o /h5_read_sydr

# build target for afl++

export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export LDFLAGS="$CFLAGS"

rm -rf build-dir && mkdir build-dir && cd build-dir
cmake -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_BUILD_TYPE:STRING=Release \
    -DBUILD_SHARED_LIBS:BOOL=OFF \
    -DBUILD_TESTING:BOOL=OFF \
    -DCMAKE_VERBOSE_MAKEFILES:BOOL=ON \
    -DHDF5_BUILD_EXAMPLES:BOOL=OFF \
    -DHDF5_BUILD_TOOLS:BOOL=OFF \
    -DHDF5_ENABLE_SANITIZERS:BOOL=ON \
    -DHDF5_ENABLE_Z_LIB_SUPPORT:BOOL=ON \
    ..

# Make the build verbose for easy logging inspection
cmake --build . --verbose --config Release -j$(nproc)
cd ..

export CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export LDFLAGS="$CFLAGS"

$CC $CFLAGS -std=c99 -I./src -I./build-dir/src -I./src/H5FDsubfiling/ \
    /h5_read_fuzzer.c ./build-dir/bin/libhdf5.a  -lz -o /h5_read_afl

# build target for coverage

export CC=clang
export CXX=clang++
export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export LDFLAGS="$CFLAGS"

rm -rf build-dir && mkdir build-dir && cd build-dir
cmake -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_BUILD_TYPE:STRING=Release \
    -DBUILD_SHARED_LIBS:BOOL=OFF \
    -DBUILD_TESTING:BOOL=OFF \
    -DCMAKE_VERBOSE_MAKEFILES:BOOL=ON \
    -DHDF5_BUILD_EXAMPLES:BOOL=OFF \
    -DHDF5_BUILD_TOOLS:BOOL=OFF \
    -DHDF5_ENABLE_SANITIZERS:BOOL=ON \
    -DHDF5_ENABLE_Z_LIB_SUPPORT:BOOL=ON \
    ..

# Make the build verbose for easy logging inspection
cmake --build . --verbose --config Release -j$(nproc)
cd ..

$CC $CFLAGS -pthread /opt/StandaloneFuzzTargetMain.c -c -o /StandaloneFuzzTargetMain.o

$CC $CFLAGS -std=c99 -I./src -I./build-dir/src -I./src/H5FDsubfiling/ \
    /StandaloneFuzzTargetMain.o /h5_read_fuzzer.c ./build-dir/bin/libhdf5.a -ldl -lm -lz -o /h5_read_cov
