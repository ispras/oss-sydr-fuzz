#!/bin/bash -eux
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

if [[ $CONFIG = "libfuzzer" ]]
then
  export SUFFIX="fuzz"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,bounds,integer,null"
  export CXXFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,bounds,integer,null"
  export ENGINE="$(find $(llvm-config --libdir) -name libclang_rt.fuzzer-x86_64.a | head -1)"
fi

if [[ $CONFIG = "afl" ]]
then
  export SUFFIX="afl"
  export CC=afl-clang-fast
  export CXX=afl-clang-fast++
  export CFLAGS="-g -fsanitize=undefined,address,bounds,integer,null"
  export CXXFLAGS="-g -fsanitize=undefined,address,bounds,integer,null"
  export ENGINE="/afl.o"
  $CXX $CXXFLAGS -c -o $ENGINE /afl.cc
fi

if [[ $CONFIG = "sydr" ]]
then
  export SUFFIX="sydr"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g"
  export CXXFLAGS="-g"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
fi

if [[ $CONFIG = "coverage" ]]
then
  export SUFFIX="cov"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g"
  export CXXFLAGS="-g"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
fi

# Build libpng
cd /
wget http://download.sourceforge.net/libpng/libpng-1.6.37.tar.gz
tar -xvzf libpng-1.6.37.tar.gz
mv /libpng-1.6.37/ /libpng-1.6.37-$SUFFIX/
cd /libpng-1.6.37-$SUFFIX/
cmake -DCMAKE_C_COMPILER=$CC \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -S . -B build/
cd build
cmake --build . -j$(nproc)

# Build libjpeg-turbo
cd /
wget https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/2.1.3.tar.gz
tar -xvzf 2.1.3.tar.gz
mv /libjpeg-turbo-2.1.3/ /libjpeg-turbo-2.1.3-$SUFFIX/
cd /libjpeg-turbo-2.1.3-$SUFFIX/
cmake -G"Unix Makefiles" -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DENABLE_STATIC=1 \
      -DENABLE_SHARED=0 -DWITH_JPEG8=1 \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -S . -B build/
cd build/
make -j$(nproc)

# Build zlib
cd /
git clone https://github.com/madler/zlib.git zlib_$SUFFIX
cd zlib_$SUFFIX
git checkout v1.2.13
CC=$CC CXX=$CXX \
      CFLAGS="$CFLAGS" \
      CXXFLAGS="$CXXFLAGS" \
      ./configure
make -j$(nproc)

# Build torchvision
cd /vision_$SUFFIX/

Torch_DIR=/pytorch_$SUFFIX/ \
      cmake \
      -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DENGINE=$ENGINE -DSUFFIX=$SUFFIX \
      -DJPEG_LIBRARY=/libjpeg-turbo-2.1.3-$SUFFIX/build/libjpeg.a \
      -DPNG_LIBRARY=/libpng-1.6.37-$SUFFIX/build/libpng.a \
      -DZLIB_LIBRARY=/zlib_$SUFFIX/libz.a \
      -Donnx_LIBRARY=/pytorch_$SUFFIX/build/lib/libonnx.a \
      -Donnx_proto_LIBRARY=/pytorch_$SUFFIX/build/lib/libonnx_proto.a \
      -Dfoxi_loader_LIBRARY=/pytorch_$SUFFIX/build/lib/libfoxi_loader.a \
      -DCMAKE_C_COMPILER_ID=GNU -DCMAKE_CXX_COMPILER_ID=GNU \
      -S . -B build/
cd build/
cmake --build . -j$(nproc)

