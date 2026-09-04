#!/bin/bash
#
# Copyright 2026 ISP RAS
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

if [[ $TARGET = "fuzzer" ]]
then
  export SUFFIX="fuzzer"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined,bounds,null,float-divide-by-zero -fPIC"
  export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined,bounds,null,float-divide-by-zero -std=c++20 -fPIC"
  export ENGINE="$(find $(llvm-config --libdir) -name libclang_rt.fuzzer-x86_64.a | head -1)"
fi

if [[ $TARGET = "afl" ]]
then
  export SUFFIX="afl"
  export CC=afl-clang-fast
  export CXX=afl-clang-fast++
  export CFLAGS="-g -fsanitize=address,undefined,bounds,null,float-divide-by-zero -fPIC"
  export CXXFLAGS="-g -fsanitize=address,undefined,bounds,null,float-divide-by-zero -std=c++20 -fPIC"
  export ENGINE="$(find /usr/local/ -name 'libAFLDriver.a' | head -1)"
fi

if [[ $TARGET = "sydr" ]]
then
  export SUFFIX="sydr"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fPIC"
  export CXXFLAGS="-g -std=c++20 -fPIC"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
fi

if [[ $TARGET = "cov" ]]
then
  export SUFFIX="cov"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -fPIC"
  export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -std=c++20 -fPIC"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
fi

# Build libjpeg
cd /libjpeg-turbo
mkdir build_$SUFFIX && cd build_$SUFFIX
cmake -G"Unix Makefiles" -DCMAKE_C_COMPILER=$CC -DCMAKE_C_FLAGS="$CFLAGS" \
    -DENABLE_STATIC=ON -DENABLE_SHARED=OFF -DWITH_TOOLS=OFF -DWITH_TESTS=OFF ..
make -j

# Build libpng
cd /libpng
mkdir build_$SUFFIX && cd build_$SUFFIX
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_C_FLAGS="$CFLAGS" \
    -DPNG_SHARED=OFF -DPNG_STATIC=ON -DPNG_TOOLS=OFF -DPNG_HARDWARE_OPTIMIZATIONS=OFF ..
make -j

# Build zlib
cd /zlib
mkdir build_$SUFFIX && cd build_$SUFFIX
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_C_FLAGS="$CFLAGS" \
    -DZLIB_BUILD_SHARED=OFF -DZLIB_INSTALL=OFF ..
make -j

# Build libwebp
cd /libwebp
mkdir build_$SUFFIX && cd build_$SUFFIX
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -DWEBP_LINK_STATIC=ON ..
make -j

# Build libheif
cd /libheif
mkdir build_$SUFFIX && cd build_$SUFFIX
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -DWITH_EXAMPLES=OFF -DWITH_EXAMPLE_HEIF_THUMB=OFF \
    -DWITH_EXAMPLE_HEIF_VIEW=OFF -DWITH_GDK_PIXBUF=OFF ..
make -j

# Build libavif
cd /libavif
mkdir build_$SUFFIX && cd build_$SUFFIX
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -DAVIF_LIBYUV=LOCAL ..
make -j

# Build PyTorch
cd /pytorch
python3 setup.py clean
CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS MAX_JOBS=$(nproc) \
    USE_ITT=0 USE_TENSORPIPE=0 USE_FBGEMM=0 BUILD_BINARY=0 USE_MKL=0 USE_DISTRIBUTED=1 \
    USE_MPI=0 TP_BUILD_LIBUV=1 BUILD_TEST=0 BUILD_SHARED_LIBS=OFF USE_OPENMP=0 \
    USE_MKLDNN=0 USE_GLOO=0 USE_CUDA=0 USE_XPU=0 \
    python3 setup.py build_clib

# Build TorchCodec
mkdir /$SUFFIX
cd /torchcodec/src/torchcodec/_core
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_PREFIX_PATH="/pytorch" -DSUFFIX="$SUFFIX" -DENGINE="${ENGINE}" -B build_$SUFFIX -S .
cmake --build build_$SUFFIX -j$(nproc)
cmake --install build_$SUFFIX
