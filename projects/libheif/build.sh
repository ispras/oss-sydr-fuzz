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


# Build dependencies.
export CC=clang
export CXX=clang++
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined"
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined"

export LIB_FUZZING_ENGINE=/usr/lib/clang/14.0.6/lib/linux/libclang_rt.fuzzer-x86_64.a

export DEPS_PATH="$(pwd)/deps"
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


#build fuzzers
cd ../../../libheif
mkdir build
cd build
cmake .. --preset=fuzzing \
      -DFUZZING_LINKER_OPTIONS="$LIB_FUZZING_ENGINE" \
      -DFUZZING_C_COMPILER=$CC -DFUZZING_CXX_COMPILER=$CXX \
      -DWITH_DEFLATE_HEADER_COMPRESSION=OFF \
      -DFUZZING_COMPILE_OPTIONS="-g -fsanitize=fuzzer-no-link,address,undefined"

make -j$(nproc)

cd ../

#build coverage fuzzers
export CFLAGS="-O1 -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-O1 -fprofile-instr-generate -fcoverage-mapping"
export CC=clang
export CXX=clang++

mkdir -p coverage_build
cd coverage_build
cmake .. --preset=fuzzing \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DWITH_DEFLATE_HEADER_COMPRESSION=OFF

make -j$(nproc)

#build for sydr

cd ../../../

clang -c /opt/StandaloneFuzzTargetMain.c -o StandaloneFuzzTargetMain.o

cd src/libheif

export CFLAGS="-g"
export CXXFLAGS="-g"
export CC=clang
export CXX=clang++
export LIB_FUZZING_ENGINE="/StandaloneFuzzTargetMain.o"  

mkdir -p sydr_build
cd sydr_build
cmake .. --preset=fuzzing \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DFUZZING_ENGINE="$LIB_FUZZING_ENGINE"
    
make -j$(nproc)

cd ../../../

#copy builded fuzzers

mkdir fuzzers
mkdir coverage_fuzzers
mkdir sydr_fuzzers

cp src/libheif/build/fuzzing/*_fuzzer ./fuzzers

for fuzzer in src/libheif/coverage_build/fuzzing/*_fuzzer; do
  base=$(basename "$fuzzer")                
  cp "$fuzzer" "./coverage_fuzzers/${base}_coverage"
done

for fuzzer in src/libheif/sydr_build/fuzzing/*_fuzzer; do
  base=$(basename "$fuzzer")                
  cp "$fuzzer" "./sydr_fuzzers/${base}_sydr"
done

cp src/libheif/fuzzing/data/dictionary.txt ./box-fuzzer.dict
cp src/libheif/fuzzing/data/dictionary.txt ./file-fuzzer.dict

find src/libheif/fuzzing/data/corpus -type f -name "*.heic" -exec zip -j file-fuzzer_seed_corpus.zip {} +
unzip file-fuzzer_seed_corpus.zip -d file-fuzzer_seed_corpus

rm -rf file-fuzzer_seed_corpus.zip