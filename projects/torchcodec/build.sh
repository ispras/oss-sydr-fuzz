#!/bin/bash
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

if [[ $TARGET = "libfuzzer" ]]
then
  export SUFFIX="fuzz"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,bounds,integer,null -fPIC"
  export CXXFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,bounds,integer,null -std=c++17 -fPIC"
  export LDFLAGS="$CFLAGS"
  export ENGINE="$(find $(llvm-config --libdir) -name libclang_rt.fuzzer-x86_64.a | head -1)"
  export BUILD_SAVERS="OFF"
fi

if [[ $TARGET = "afl" ]]
then
  export SUFFIX="afl"
  export CC=afl-clang-fast
  export CXX=afl-clang-fast++
  export CFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow -fPIC"
  export CXXFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow -std=c++17 -fPIC"
  export LDFLAGS="$CFLAGS"
  export ENGINE="$(find /usr/local/ -name 'libAFLDriver.a' | head -1)"
  export BUILD_SAVERS="OFF"
fi

if [[ $TARGET = "sydr" ]]
then
  export SUFFIX="sydr"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fPIC"
  export CXXFLAGS="-g -std=c++17 -fPIC"
  export LDFLAGS="$CFLAGS"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
  export BUILD_SAVERS="ON"
fi

if [[ $TARGET = "coverage" ]]
then
  export SUFFIX="cov"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -fPIC"
  export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -std=c++17 -fPIC"
  export LDFLAGS="$CFLAGS"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
  export BUILD_SAVERS="OFF"
fi

# Build pytorch

cd /pytorch

# clean artifacts from previous build pytorch
python3 setup.py clean

CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS MAX_JOBS=$(nproc) USE_ITT=0 USE_FBGEMM=0 BUILD_BINARY=1 USE_STATIC_MKL=1 USE_DISTRIBUTED=1 \
        USE_MPI=0 TP_BUILD_LIBUV=0 USE_TENSORPIPE=0 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=0 BUILD_TEST=0 BUILD_SHARED_LIBS=OFF BUILD_BINARY=OFF USE_OPENMP=0 USE_MKLDNN=0 USE_GLOO=0 \
        python3 setup.py build_clib


# Build zlib
cd /zlib
make clean
CC=$CC CXX=$CXX \
CFLAGS="$CFLAGS" \
CXXFLAGS="$CXXFLAGS" \
./configure --prefix=/zlib/install
make -j$(nproc)
make install

# Build ffmpeg
cd /ffmpeg
make clean

./configure \
  --prefix=/ffmpeg/install \
  --cc=$CC \
  --cxx=$CXX \
  --disable-shared \
  --enable-static \
  --enable-zlib \
  --extra-cflags="-I/zlib/install/include" \
  --extra-ldflags="-L/zlib/install/lib -lz"

make -j$(nproc)
make install


# Build torccodec
cd /codec
rm -rf build
Torch_DIR=/pytorch/ \
      cmake \
      -DCMAKE_C_COMPILER=$CC \
      -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DBUILD_SAVERS=${BUILD_SAVERS:-} \
      -DENGINE=$ENGINE \
      -DSUFFIX=$SUFFIX \
      -S . -B build/

cd build/
cmake --build . -j$(nproc)
cmake --install .

if [[ $TARGET = "sydr" ]]; 
then
  # Generate tensors from corpus
  cd /

  for filename in /wav_corpus/*; do 
      if ./save_tensor "$filename"; then
          mv /wav_corpus/*.tensor /wav_tensor/
      fi
  done
fi

