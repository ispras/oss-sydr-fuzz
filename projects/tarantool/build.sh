#!/bin/bash -eu
# Copyright 2021 Google LLC
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

git apply --ignore-space-change --ignore-whitespace test/fuzz/disable_logging.diff

CC=clang
CXX=clang++
CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    # Specific to Tarantool
    -DENABLE_FUZZER=ON
    -DOSS_FUZZ=OFF
    -DENABLE_ASAN=ON
    -DENABLE_UB_SANITIZER=ON
    -DCMAKE_BUILD_TYPE=Release

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

# Build the project and fuzzers.
[[ -e build ]] && rm -rf build
cmake "${cmake_args[@]}" -S . -B build
make -j$(nproc) VERBOSE=1 -C build fuzzers

# Archive and copy to $OUT seed corpus if the build succeeded.
for f in $(ls build/test/fuzz/*_fuzzer);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_fuzzer//')
  corpus_dir="test/static/corpus/$module"
  echo "Copying for $module";
  cp $f /
  [[ -e $corpus_dir ]] && cp -r $corpus_dir /corpus_$module
done

# Build the project for Sydr.
CFLAGS="-g"
CXXFLAGS="-g"
LDFLAGS=""

cmake_args=(
    # Specific to Tarantool
    -DENABLE_FUZZER=ON
    -DOSS_FUZZ=ON
    -DCMAKE_BUILD_TYPE=Release
    -DENABLE_ASAN=OFF
    -DENABLE_UB_SANITIZER=OFF

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
mkdir -p build/test/fuzz
export LIB_FUZZING_ENGINE="$PWD/build/test/fuzz/main.o"
$CC $CFLAGS -c test/fuzz/main.c -o $LIB_FUZZING_ENGINE
cmake "${cmake_args[@]}" -S . -B build
make -j$(nproc) VERBOSE=1 -C build fuzzers
for f in $(ls build/test/fuzz/*_fuzzer);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_fuzzer//')
  echo "Copying for Sydr $module";
  cp $f /"$module"_sydr
done
