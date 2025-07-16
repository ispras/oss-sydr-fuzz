#!/bin/bash
#
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

export SUFFIX="afl"
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow"
export CXXFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow"
export LDFLAGS="$CFLAGS"
export ENGINE="$(find /usr/local/ -name 'libAFLDriver.a' | head -1)"

# Build libsox
cd /libsox
autoreconf -i
make clean || true
./configure
make
make install

# Build pytorch
cd /pytorch
rm -rf build CMakaCache.txt CMakeFiles/
mkdir build && cd build

# Build pytoch
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_CXX_STANDART=17 \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DUSE_CUDNN=0 \
  -DUSE_CUSPARSELT=0 \
  -DUSE_CUDSS=0 \
  -DUSE_FBGEMM=0 \
  -DUSE_KINETO=0 \
  -DUSE_NUMPY=0 \
  -DBUILD_TEST=0 \
  -DUSE_MKLDNN=0 \
  -DUSE_NNPACK=0 \
  -DUSE_DISTRIBUTED=0 \
  -DUSE_TENSORPIPE=0 \
  -DUSE_GLOO=0 \
  -DUSE_MPI=0 \
  -DUSE_OPENMP=0 \
  -DUSE_FLASH_ATTENTION=0 \
  -DUSE_ITT=0 \
  -DUSE_MEM_EFF_ATTENTION=0 \

cmake --build . -j$(nproc)
cmake --install .

# Build your fuzz target
cd /audio
rm -rf build
Torch_DIR=/pytorch/ \
      cmake \
      -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS -std=c++17" \
      -DENGINE=$ENGINE -DSUFFIX=$SUFFIX \
      -Donnx_LIBRARY=/pytorch/build/lib/libonnx.a \
      -Donnx_proto_LIBRARY=/pytorch/build/lib/libonnx_proto.a \
      -Dfoxi_loader_LIBRARY=/pytorch/build/lib/libfoxi_loader.a \
      -DCMAKE_C_COMPILER_ID=GNU -DCMAKE_CXX_COMPILER_ID=GNU \
      -DBUILD_SHARED_LIBS=OFF \
      -S . -B build/

cd build
cmake --build . -j$(nproc)
cmake --install .

