#!/bin/bash -eu
# Copyright (C) 2023 ISP RAS
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

export MAIN_OBJ=""

if [[ $CONFIG = "libfuzzer" ]]
then
    export CC="clang"
    export CXX="clang++"
    export CFLAGS="-g -O0 -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
    export CXXFLAGS="-g -std=c++11 -O0 -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
    export LINK_FLAGS="-g -std=c++11 -O0 -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
    export SUFFIX="fuzz"
fi

if [[ $CONFIG = "afl" ]]
then
    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
    export CFLAGS="-g -O0 -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
    export CXXFLAGS="-g -std=c++11 -O0 -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
    export LINK_FLAGS="-g -std=c++11 -O0 -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
    export SUFFIX="afl"
fi

if [[ $CONFIG = "sydr" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -O0"
    export CXXFLAGS="$CFLAGS -std=c++11"
    export LINK_FLAGS="$CFLAGS -std=c++11"
    export SUFFIX="sydr"
fi

if [[ $CONFIG = "coverage" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping"
    export CXXFLAGS="$CFLAGS -std=c++11"
    export LINK_FLAGS="$CFLAGS -std=c++11"
    export SUFFIX="cov"
fi

if [[ $CONFIG = "sydr" || $CONFIG = "coverage" ]]
then
    $CC $CFLAGS -c -o /main.o /opt/StandaloneFuzzTargetMain.c
    MAIN_OBJ="/main.o"
fi

cd /tinygltf

$CXX $LINK_FLAGS -I/tinygltf -o /loader_example_$SUFFIX /loader_example.cc $MAIN_OBJ

$CXX $LINK_FLAGS -I/tinygltf -o /fuzz_gltf_$SUFFIX /tinygltf/tests/fuzzer/fuzz_gltf.cc $MAIN_OBJ
