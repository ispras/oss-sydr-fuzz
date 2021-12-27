#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

CC=clang
CXX=clang++
CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export LIB_FUZZING_ENGINE=$(find /usr/lib/clang -name libclang_rt.fuzzer-x86_64.a)

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    # Specific to Expat
    -DEXPAT_BUILD_FUZZERS=ON
    -DEXPAT_OSSFUZZ_BUILD=ON
    -DEXPAT_SHARED_LIBS=OFF

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

mkdir -p build
cd build
cmake ../expat "${cmake_args[@]}"
make -j$(nproc)

for fuzzer in fuzz/*;
do
  cp $fuzzer /
  fuzzer_name=$(basename $fuzzer)
  if [[ ${fuzzer_name} =~ ^.*UTF-16$ ]];
  then
    cp ../xml_UTF_16.dict /${fuzzer_name}.dict
  elif [[ ${fuzzer_name} =~ ^.*UTF-16LE$ ]];
  then
    cp ../xml_UTF_16LE.dict /${fuzzer_name}.dict
  elif [[ ${fuzzer_name} =~ ^.*UTF-16BE$ ]];
  then
    cp ../xml_UTF_16BE.dict /${fuzzer_name}.dict
  else
    cp ../xml.dict /${fuzzer_name}.dict
  fi
done

# Build the project for Sydr.
CFLAGS="-g"
CXXFLAGS="-g"
LDFLAGS=""
export LIB_FUZZING_ENGINE="$PWD/main.o"

cmake_args=(
    # Specific to Expat
    -DEXPAT_BUILD_FUZZERS=ON
    -DEXPAT_OSSFUZZ_BUILD=ON
    -DEXPAT_SHARED_LIBS=OFF

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

cd ..
rm -rf build
mkdir -p build
cd build
$CC $CFLAGS -c ../main.c -o $LIB_FUZZING_ENGINE
cmake ../expat "${cmake_args[@]}"
make -j$(nproc)

for fuzzer in fuzz/*;
do
  fuzzer_name=$(basename $fuzzer)
  cp $fuzzer /${fuzzer_name}_sydr
done
