#!/bin/bash
# Copyright 2025 ISP RAS
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

if [[ $TARGET == "fuzz" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,null,float-divide-by-zero"
    export CXXFLAGS=$CFLAGS
elif [[ $TARGET == "afl" ]]
then
    export CC=afl-clang-fast
    export CXX=afl-clang-fast++
    export CFLAGS="-g -fsanitize=address,bounds,integer,null,float-divide-by-zero"
    export CXXFLAGS=$CFLAGS
elif [[ $TARGET == "sydr" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g"
    export CXXFLAGS=$CFLAGS
    clang -c /opt/StandaloneFuzzTargetMain.c -o /StandaloneFuzzTargetMain.o
elif [[ $TARGET == "cov" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    export CXXFLAGS=$CFLAGS
    clang -c /opt/StandaloneFuzzTargetMain.c -o /StandaloneFuzzTargetMain.o
fi

# Build targets
mkdir build && cd build

cmake -DCMAKE_C_COMPILER=$CC \
      -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DBUILD_SHARED_LIBS=OFF \
      ..
make -j

export EXTRAFLAGS=""
if [[ $TARGET == "fuzz" || $TARGET == "afl" ]]
then
    export CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,null,float-divide-by-zero"
fi
if [[ $TARGET == "sydr" || $TARGET == "cov" ]]
then
    export EXTRAFLAGS="/StandaloneFuzzTargetMain.o -lpthread -ldl"
fi

$CXX $CXXFLAGS -I/rlottie/inc -O2 -o /render_${TARGET} ../render_fuzz.cpp librlottie.a $EXTRAFLAGS
$CXX $CXXFLAGS -I/rlottie/inc -O2 -o /load_${TARGET} ../load_fuzz.cpp librlottie.a $EXTRAFLAGS

cd .. && rm -rf build
