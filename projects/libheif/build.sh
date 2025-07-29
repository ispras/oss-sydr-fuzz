#!/bin/bash -eu
# Copyright 2019 Google Inc.
# Modifications copyright (C) 2025 ISP RAS
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
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
    export CXXFLAGS=$CFLAGS
    export LIB_FUZZING_ENGINE=`find /usr/lib -name "libclang_rt.fuzzer-x86_64.a" | head -n1`
elif [[ $TARGET == "afl" ]]
then
    export CC=afl-clang-fast
    export CXX=afl-clang-fast++
    export CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
    export CXXFLAGS=$CFLAGS
    export LIB_FUZZING_ENGINE="/usr/local/lib/afl/libAFLDriver.a"
elif [[ $TARGET == "sydr" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g"
    export CXXFLAGS=$CFLAGS
    clang -c /opt/StandaloneFuzzTargetMain.c -o /StandaloneFuzzTargetMain.o
    export LIB_FUZZING_ENGINE=/StandaloneFuzzTargetMain.o
elif [[ $TARGET == "cov" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    export CXXFLAGS=$CFLAGS
    clang -c /opt/StandaloneFuzzTargetMain.c -o /StandaloneFuzzTargetMain.o
    export LIB_FUZZING_ENGINE=/StandaloneFuzzTargetMain.o
fi


# Build dependencies.
export DEPS_PATH="/deps_${TARGET}"
mkdir -p "$DEPS_PATH"

cd x265/build/linux
cmake -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
    -DENABLE_SHARED:bool=off \
    ../../source
make clean
make -j$(nproc) x265-static
make install

cd ../../../libde265
./autogen.sh
./configure \
    --prefix="$DEPS_PATH" \
    --disable-shared \
    --enable-static \
    --disable-dec265 \
    --disable-sherlock265 \
    --disable-hdrcopy \
    --disable-enc265 \
    --disable-acceleration_speed
make clean
make -j$(nproc)
make install

mkdir -p ../aom/build/linux
cd ../aom/build/linux
cmake -G "Unix Makefiles" \
  -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
  -DENABLE_SHARED:bool=off -DCONFIG_PIC=1 \
  -DENABLE_EXAMPLES=0 -DENABLE_DOCS=0 -DENABLE_TESTS=0 \
  -DCONFIG_SIZE_LIMIT=1 \
  -DDECODE_HEIGHT_LIMIT=12288 -DDECODE_WIDTH_LIMIT=12288 \
  -DDO_RANGE_CHECK_CLAMP=1 \
  -DAOM_MAX_ALLOCABLE_MEMORY=536870912 \
  -DAOM_TARGET_CPU=generic \
  ../../
make clean
make -j$(nproc)
make install

# Remove shared libraries to avoid accidental linking against them.
rm -f $DEPS_PATH/lib/*.so
rm -f $DEPS_PATH/lib/*.so.*

# Build project
cd /libheif
mkdir build_${TARGET}
cd build_${TARGET}
cmake .. --preset=fuzzing \
      -DFUZZING_LINKER_OPTIONS="$LIB_FUZZING_ENGINE" \
      -DFUZZING_C_COMPILER=$CC -DFUZZING_CXX_COMPILER=$CXX \
      -DWITH_DEFLATE_HEADER_COMPRESSION=OFF \
      -DFUZZING_COMPILE_OPTIONS="$CFLAGS"
make -j$(nproc)

for fuzzer in fuzzing/*_fuzzer; do
  name=$(basename "$fuzzer" | cut -d'_' -f1)
  cp "$fuzzer" "/${name}_${TARGET}"
done

cd /
