#!/bin/bash -eu
#
# Copyright 2023 ISP RAS
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

export WORK="/work"

if [[ $CONFIG = "libfuzzer" ]]
then
  export CXX=clang++
  export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
  export CC=clang
  export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
  export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero\
                     -std=c++11 -I$WORK/include /tiff_read_rgba_fuzzer.cc -o /tiff_read_rgba_fuzzer"
fi

if [[ $CONFIG = "afl" ]]
then
  export CXX=afl-clang-fast++
  export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
  export CC=afl-clang-fast
  export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
  export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero\
                      -std=c++11 -I$WORK/include /tiff_read_rgba_fuzzer.cc -o /tiff_read_rgba_afl"
fi

if [[ $CONFIG = "sydr" ]]
then
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -lm"
  export CXXFLAGS="-g -lm"
  export LINK_FLAGS="$CXXFLAGS -o /tiff_read_rgba_sydr tiff_read_rgba_fuzzer.o main.o"

  $CC $CFLAGS -c -o main.o /opt/StandaloneFuzzTargetMain.c
  $CXX $CXXFLAGS -c -I$WORK/include -o tiff_read_rgba_fuzzer.o /tiff_read_rgba_fuzzer.cc
fi

if [[ $CONFIG = "coverage" ]]
then
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -lm"
  export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -lm"
  export LINK_FLAGS="$CXXFLAGS -o /tiff_read_rgba_cov tiff_read_rgba_fuzzer.o main.o"

  $CC $CFLAGS -c -o main.o /opt/StandaloneFuzzTargetMain.c
  $CXX $CXXFLAGS -c -I$WORK/include -o tiff_read_rgba_fuzzer.o /tiff_read_rgba_fuzzer.cc
fi

# Build zlib
pushd "/zlib"
rm -rf build
cmake . -DCMAKE_INSTALL_PREFIX="$WORK" -DENABLE_STATIC=on -DENABLE_SHARED=off -B build
cd build && cmake --build . -j$(nproc) && cmake --install . && cd ..
popd

# Build libjpeg-turbo
pushd "/libjpeg-turbo"
rm -rf build
cmake . -DCMAKE_INSTALL_PREFIX="$WORK" -DENABLE_STATIC=on -DENABLE_SHARED=off -B build
cd build && cmake --build . -j$(nproc) && cmake --install . && cd ..
popd

# Build libjbig
pushd "/jbigkit"
make clean
PATH=$PWD:$PATH make lib
cp /jbigkit/libjbig/*.a "$WORK/lib/"
cp /jbigkit/libjbig/*.h "$WORK/include/"
popd

rm -rf build-dir
cmake . \
      -DCMAKE_INSTALL_PREFIX=$WORK -DBUILD_SHARED_LIBS=off \
      -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" -S . -B build-dir
cd build-dir && cmake --build . -j$(nproc) && cmake --install . && cd ..

$CXX $LINK_FLAGS \
    $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a \
    $WORK/lib/libjpeg.a $WORK/lib/libjbig.a $WORK/lib/libjbig85.a

if [[ $CONFIG = "coverage" ]]
then
  mkdir afl_testcases
  (cd afl_testcases; tar xf "/afl_testcases.tgz")
  mkdir /tif
  find afl_testcases -type f -name '*.tif' -exec mv -n {} tif/ \;
fi
