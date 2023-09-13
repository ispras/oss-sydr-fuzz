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

for CONFIG in $CONFIGS; do

if [[ $CONFIG = "libfuzzer" ]]
then
  export SUFFIX="fuzz"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,bounds,integer,null"
  export CXXFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,bounds,integer,null"
  export LDFLAGS="$CFLAGS"
  export ENGINE="$(find $(llvm-config --libdir) -name libclang_rt.fuzzer-x86_64.a | head -1)"
fi

if [[ $CONFIG = "afl" ]]
then
  export SUFFIX="afl"
  export CC=afl-clang-fast
  export CXX=afl-clang-fast++
  export CFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow"
  export CXXFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow"
  export LDFLAGS="$CFLAGS"
  export ENGINE="$(find /usr/local/ -name 'libAFLDriver.a' | head -1)"
fi

if [[ $CONFIG = "sydr" ]]
then
  export SUFFIX="sydr"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g"
  export CXXFLAGS="-g"
  export LDFLAGS="$CFLAGS"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
fi

if [[ $CONFIG = "coverage" ]]
then
  export SUFFIX="cov"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
  export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
  export LDFLAGS="$CFLAGS"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
fi

# Build libsox

cd /libsox
autoreconf -i
make clean || true
./configure
make
make install

# Build pytorch

cd /pytorch

# clean artifacts from previous build
python3 setup.py clean

MAX_JOBS=$(nproc) USE_FBGEMM=0 BUILD_BINARY=1 CC=$CC CXX=$CXX USE_STATIC_MKL=1 \
        USE_DISTRIBUTED=0 USE_MPI=0 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=1 BUILD_TEST=0 \
        BUILD_SHARED_LIBS=OFF USE_OPENMP=0 USE_MKLDNN=0 USE_ITT=0 \
        CXXFLAGS="$CXXFLAGS" CFLAGS="$CFLAGS" \
        CMAKE_THREAD_LIBS_INIT="$(find /usr/lib -name 'libpthread.so*' | head -1)" \
        python3 setup.py build

# Build torchaudio

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
    -S . -B build/
cd build
cmake --build . -j$(nproc)
cmake --install .

done
