#!/bin/bash
# Copyright 2023 Google LLC
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

export MAIN_OBJ=""

if [[ $CONFIG = "libfuzzer" ]]
then
    export CC="clang"
    export CXX="clang++"
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
    export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
    export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
	export SUFFIX="fuzz"
fi

if [[ $CONFIG = "afl" ]]
then
    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
    export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
    export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
    export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
	export SUFFIX="afl"
fi

if [[ $CONFIG = "sydr" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g"
    export CXXFLAGS="$CFLAGS"
    export LINK_FLAGS="$CFLAGS"
	export SUFFIX="sydr"
fi

if [[ $CONFIG = "coverage" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    export CXXFLAGS="$CFLAGS"
    export LINK_FLAGS="$CFLAGS"
    export SUFFIX="cov"
fi

cd server
rm -rf build
mkdir build
cd build
cmake ../ -DDISABLE_SHARED=ON -LH
make clean

# Ensure we do static linking
sed -i 's/libmariadb SHARED/libmariadb STATIC/g' ../libmariadb/libmariadb/CMakeLists.txt
make
rm CMakeCache.txt

# Build fuzzers
if [[ $CONFIG = "sydr" || $CONFIG = "coverage" ]]
then
    $CC $CFLAGS -c -o /main.o /opt/StandaloneFuzzTargetMain.c
    MAIN_OBJ="/main.o"
fi

INCLUDE_DIRS="-I/server/wsrep-lib/include -I/server/wsrep-lib/wsrep-API/v26 -I/server/build/include -I/server/include/providers -I/server/include -I/server/sql -I/server/regex -I/server/unittest/mytap"
$CC $CFLAGS $INCLUDE_DIRS -c /fuzz_json.c -o ./fuzz_json.o

INCLUDE_DIRS="-I/server/wsrep-lib/include -I/server/wsrep-lib/wsrep-API/v26 -I/server/build/include -I/server/include/providers -I/server/include -I/server/sql -I/server/regex -I/server/unittest/mytap"
$CC $CFLAGS $INCLUDE_DIRS -c /fuzz_get.c -o ./fuzz_get.o

# Link with CXX to support centipede
$CXX $LINK_FLAGS fuzz_json.o -o /fuzz_json_$SUFFIX \
	-Wl,--start-group ./unittest/mytap/libmytap.a ./strings/libstrings.a \
	./dbug/libdbug.a ./mysys/libmysys.a -Wl,--end-group -lz -ldl -lpthread $MAIN_OBJ

$CXX $LINK_FLAGS fuzz_get.o -o /fuzz_get_$SUFFIX \
	-Wl,--start-group ./unittest/mytap/libmytap.a ./strings/libstrings.a \
	./dbug/libdbug.a ./mysys/libmysys.a -Wl,--end-group -lz -ldl -lpthread $MAIN_OBJ
