#!/bin/bash -eu
# Copyright 2025 Google LLC
# Modifications copyright (C) 2026 ISP RAS
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

if [[ $TARGET == "fuzzer" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,null,float-divide-by-zero"
    export CXXFLAGS=$CFLAGS
elif [[ $TARGET == "afl" ]]
then
    export CC=afl-clang-fast
    export CXX=afl-clang-fast++
    export CFLAGS="-g -fsanitize=address,bounds,null,float-divide-by-zero"
    export CXXFLAGS=$CFLAGS
elif [[ $TARGET == "sydr" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g"
    export CXXFLAGS=$CFLAGS
elif [[ $TARGET == "cov" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    export CXXFLAGS=$CFLAGS
fi

# ===== Build Sqlite =====
SQLITE_VER=sqlite-autoconf-3480000
cd /${SQLITE_VER}
make clean && make uninstall
./configure --enable-static --disable-shared
make -j"$(nproc)"
make install

# ===== Build zeroMQ =====
cd /libzmq
rm -rf build
mkdir build && cd build
cmake .. -DBUILD_SHARED=OFF -DBUILD_STATIC=ON -DZMQ_BUILD_TESTS=OFF
make -j"$(nproc)"
make install

# ===== Build BehaviorTree.CPP =====
mkdir "/${TARGET}"
cd /behaviortreecpp
rm -rf build
mkdir build && cd build

if [[ $TARGET == "sydr" || $TARGET == "cov" ]]
then
    $CC $CFLAGS -c /opt/StandaloneFuzzTargetMain.c -o main_$TARGET.o
    export LIB_FUZZING_ENGINE="${PWD}/main_$TARGET.o"
fi

CMAKE_FLAGS=(
  "-DCMAKE_BUILD_TYPE=Release"
  "-DENABLE_FUZZING=ON"
  "-DFORCE_STATIC_LINKING=ON"
  "-DBUILD_TESTING=OFF"
)

cmake .. "${CMAKE_FLAGS[@]}"
make -j"$(nproc)"

for fuzz_target in bb bt script; do
    cp "${fuzz_target}_fuzzer" "/${TARGET}/${fuzz_target}_${TARGET}"
done
