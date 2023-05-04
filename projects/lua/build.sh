#!/bin/bash -eu
#
# Copyright 2021 Google LLC
# Modifications copyright (C) 2021 ISP RAS
# Modifications copyright (C) 2023 Sergey Bronnikov
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
CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"

cd /testdir

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    -DUSE_LUA=ON
    -DLUA_VERSION=e15f1f2bb7a38a3c94519294d031e48508d65006
    -DOSS_FUZZ=OFF
    -DENABLE_ASAN=ON
    -DENABLE_UBSAN=ON
    -DCMAKE_BUILD_TYPE=Debug

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS}"

    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}"

    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)

# Build fuzzers.
[[ -e build ]] && rm -rf build
cmake "${cmake_args[@]}" -S . -B build -G Ninja
cmake --build build --parallel

# Archive and copy to $OUT seed corpus if the build succeeded.
for f in $(find build/tests/ -name '*_test' -type f);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_test//')
  corpus_dir="corpus/$module"
  echo "Copying for $module";
  cp $f /
  [[ -e $corpus_dir ]] && cp -r $corpus_dir /corpus_$module
  [[ -e $corpus_dir.dict ]] && cp $corpus_dir.dict /$module.dict
done

# Build the project for AFL++.
CC=afl-clang-fast
CXX=afl-clang-fast++
CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
LDFLAGS=""
export AFL_LLVM_DICT2FILE=/afl++.dict
export AFL_LLVM_DICT2FILE_NO_MAIN=1
cmake_args=(
    -DUSE_LUA=ON
    -DLUA_VERSION=e15f1f2bb7a38a3c94519294d031e48508d65006
    -DOSS_FUZZ=OFF
    -DENABLE_ASAN=ON
    -DENABLE_UBSAN=ON
    -DENABLE_COV=OFF
    -DCMAKE_BUILD_TYPE=Debug

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS}"

    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}"

    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)
[[ -e build ]] && rm -rf build
mkdir -p build/tests
cmake "${cmake_args[@]}" -S . -B build
cmake --build build --parallel
for f in $(find build/tests/ -name '*_test' -type f);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_test//')
  echo "Copying for AFL++ $module";
  cp $f /"$module"_afl
done
unset AFL_LLVM_DICT2FILE
unset AFL_LLVM_DICT2FILE_NO_MAIN

# Building cmplog instrumentation.
export AFL_LLVM_CMPLOG=1
cmake_args=(
    -DUSE_LUA=ON
    -DLUA_VERSION=e15f1f2bb7a38a3c94519294d031e48508d65006
    -DOSS_FUZZ=OFF
    -DENABLE_ASAN=ON
    -DENABLE_UBSAN=ON
    -DENABLE_COV=OFF
    -DCMAKE_BUILD_TYPE=Debug

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS}"

    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}"

    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)
[[ -e build ]] && rm -rf build
mkdir -p build/tests
cmake "${cmake_args[@]}" -S . -B build
cmake --build build --parallel
for f in $(find build/tests/ -name '*_test' -type f);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_test//')
  echo "Copying for AFL++ $module";
  cp $f /"$module"_cmplog
done
unset AFL_LLVM_CMPLOG

# Build the project for Sydr.
CC=clang
CXX=clang++
CFLAGS="-g"
CXXFLAGS="-g"
LDFLAGS=""

cmake_args=(
    -DUSE_LUA=ON
    -DLUA_VERSION=e15f1f2bb7a38a3c94519294d031e48508d65006
    -DOSS_FUZZ=ON
    -DCMAKE_BUILD_TYPE=Debug
    -DENABLE_ASAN=OFF
    -DENABLE_UBSAN=OFF
    -DENABLE_COV=OFF

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS}"

    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}"

    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)
[[ -e build ]] && rm -rf build
mkdir -p build/tests
# Workaround to build libprotobuf-mutator fuzz targets.
# They crash with StandaloneFuzzTargetMain.c
# So, we get libFuzzer without instrumentation.
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
cmake "${cmake_args[@]}" -S . -B build
cmake --build build --parallel
for f in $(find build/tests/ -name '*_test' -type f);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_test//')
  echo "Copying for Sydr $module";
  cp $f /"$module"_sydr
done

# Build the project for llvm-cov.
CC=clang
CXX=clang++
CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
LDFLAGS=""

cmake_args=(
    -DUSE_LUA=ON
    -DLUA_VERSION=e15f1f2bb7a38a3c94519294d031e48508d65006
    -DOSS_FUZZ=ON
    -DCMAKE_BUILD_TYPE=Debug
    -DENABLE_ASAN=OFF
    -DENABLE_UBSAN=OFF
    -DENABLE_DEBUG=ON
    -DENABLE_COV=ON

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS}"

    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}"

    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)
[[ -e build ]] && rm -rf build
mkdir -p build/tests
cmake "${cmake_args[@]}" -S . -B build
cmake --build build --parallel
for f in $(find build/tests/ -name '*_test' -type f);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_test//')
  echo "Copying for llvm-cov $module";
  cp $f /"$module"_cov
done
