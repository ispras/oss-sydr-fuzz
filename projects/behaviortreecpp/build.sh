#!/bin/bash -eu
# Copyright 2025 Google LLC
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

TARGET_FLAGS=""
if [[ $TARGET == "fuzzer" ]]
then
    TARGET_FLAGS="-fsanitize=fuzzer,address,bounds,null,float-divide-by-zero"
else
    $CC $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o /main_$TARGET.o
    export LIB_FUZZING_ENGINE="${PWD}/main_$TARGET.o"
    
    if [[ $TARGET == "cov" ]]
    then
        TARGET_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
    fi
fi

# ===== BUILD Sqlite =====
SQLITE_VER=sqlite-autoconf-3480000

wget https://www.sqlite.org/2025/${SQLITE_VER}.tar.gz
tar xzf ${SQLITE_VER}.tar.gz
cd ${SQLITE_VER}
./configure --enable-static --disable-shared
make -j"$(nproc)"
make install
cd ..

# ===== BUILD zeroMQ =====
git clone https://github.com/zeromq/libzmq.git
cd libzmq
mkdir build && cd build
cmake .. -DBUILD_SHARED=OFF -DBUILD_STATIC=ON -DZMQ_BUILD_TESTS=OFF
make -j"$(nproc)"
make install
cd ../..

# ===== Build  BehaviorTree.CPP =====
mkdir build_$TARGET && cd build_$TARGET

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
    cp "${fuzz_target}_fuzzer" "/${fuzzer}_${TARGET}"
done

if [[ $TARGET == "fuzzer" ]]
then
    for fuzz_target in bt script bb; do
      if [ -d "../fuzzing/corpus/${fuzz_target}_corpus" ]; then
        cp -r "../fuzzing/corpus/${fuzz_target}_corpus" "/${fuzz_target}_corpus"
      fi
    done
fi
