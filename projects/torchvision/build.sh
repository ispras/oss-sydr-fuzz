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
  export CXXFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,bounds,integer,null -std=c++17"
  export LDFLAGS="$CFLAGS"
  export ENGINE="$(find $(llvm-config --libdir) -name libclang_rt.fuzzer-x86_64.a | head -1)"
  export BUILD_SAVERS="OFF"
fi

if [[ $CONFIG = "afl" ]]
then
  export SUFFIX="afl"
  export CC=afl-clang-fast
  export CXX=afl-clang-fast++
  export CFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow"
  export CXXFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow -std=c++17"
  export LDFLAGS="$CFLAGS"
  export ENGINE="$(find /usr/local/ -name 'libAFLDriver.a' | head -1)"
  export BUILD_SAVERS="OFF"
fi

if [[ $CONFIG = "sydr" ]]
then
  export SUFFIX="sydr"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g"
  export CXXFLAGS="-g -std=c++17"
  export LDFLAGS="$CFLAGS"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
  export BUILD_SAVERS="ON"
fi

if [[ $CONFIG = "coverage" ]]
then
  export SUFFIX="cov"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
  export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -std=c++17"
  export LDFLAGS="$CFLAGS"
  export ENGINE="/StandaloneFuzzTargetMain.o"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
  export BUILD_SAVERS="OFF"
fi

# Build pytorch

cd /pytorch

# clean artifacts from previous build
rm -rf build CMakeCache.txt CMakeFiles/
mkdir build && cd build

if [[ $CONFIG = "libfuzzer" ]]
then
  cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_CXX_STANDARD=17 \
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
  -DUSE_DISTRIBUTED=1 \
  -DUSE_TENSORPIPE=0 \
  -DUSE_GLOO=0 \
  -DUSE_MPI=0 \
  -DUSE_OPENMP=0 \
  -DUSE_FLASH_ATTENTION=0 \
  -DUSE_ITT=0 \
  -DUSE_MEM_EFF_ATTENTION=0 \
  -G Ninja
fi

if [[ $CONFIG = "coverage" || $CONFIG = "sydr" || $CONFIG = "afl" ]]
then
  cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_CXX_STANDARD=17 \
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
  -G Ninja
fi

cmake --build . -j$(nproc)
cmake --install .

## Build libpng
cd /libpng-1.6.37
rm -rf build
cmake -DCMAKE_C_COMPILER=$CC \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -DCMAKE_INSTALL_PREFIX=/libpng-1.6.37/install \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
      -S . -B build/
cd build
cmake --build . -j$(nproc)
cmake --install .

# Build libjpeg-turbo
cd /libjpeg-turbo-2.1.3
rm -rf build
cmake -G"Unix Makefiles" \
      -DCMAKE_C_COMPILER=$CC \
      -DCMAKE_CXX_COMPILER=$CXX \
      -DENABLE_STATIC=1 \
      -DENABLE_SHARED=0 \
      -DWITH_JPEG8=1 \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -DCMAKE_INSTALL_PREFIX=/libjpeg-turbo-2.1.3/install \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
      -S . -B build/
cd build/
make -j$(nproc)
cmake --install .

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
  --disable-programs \
  --disable-doc \
  --disable-debug \
  --disable-shared \
  --enable-static \
  --enable-pic \
  --enable-zlib \
  --extra-cflags="-I/zlib/install/include" \
  --extra-ldflags="-L/zlib/install/lib -lz"

make -j$(nproc)
make install
# Build torchvision

cd /vision
rm -rf build
Torch_DIR=/pytorch/ \
      cmake \
      -DCMAKE_C_COMPILER=$CC \
      -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS -I/ffmpeg/install/include -I/zlib/install/include" \
      -DCMAKE_CXX_FLAGS="$CXXFLAGS -I/ffmpeg/install/include -I/zlib/install/include" \
      -DENGINE=$ENGINE \
      -DSUFFIX=$SUFFIX \
      -DBUILD_SAVERS=${BUILD_SAVERS:-} \
      -DJPEG_LIBRARY=/libjpeg-turbo-2.1.3/install/lib/libjpeg.a \
      -DJPEG_INCLUDE_DIR=/libjpeg-turbo-2.1.3/install/include \
      -DPNG_LIBRARY=/libpng-1.6.37/install/lib/libpng.a \
      -DPNG_PNG_INCLUDE_DIR=/libpng-1.6.37/install/include \
      -DZLIB_LIBRARY=/zlib/install/lib/libz.a \
      -DZLIB_INCLUDE_DIR=/zlib/install/include \
      -DFFMPEG_DIR=/ffmpeg/install \
      -DFFMPEG_INCLUDE_DIR=/ffmpeg/install/include \
      -Donnx_LIBRARY=/pytorch/build/lib/libonnx.a \
      -Donnx_proto_LIBRARY=/pytorch/build/lib/libonnx_proto.a \
      -Dfoxi_loader_LIBRARY=/pytorch/build/lib/libfoxi_loader.a \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_C_COMPILER_ID=GNU \
      -DCMAKE_CXX_COMPILER_ID=GNU \
      -S . -B build/

cd build/
cmake --build . -j$(nproc)
cmake --install .

if [[ $CONFIG = "sydr" ]]; 
then
  # Generate tensors from corpus
  cd /

  for filename in /jpeg_raw/*; do 
      if ./save_jpeg "$filename"; then
          mv /jpeg_raw/*.tensor /jpeg_tensor/
      fi
  done
  
  for filename in /png_raw/*; do 
      if ./save_png "$filename"; then
          mv /png_raw/*.tensor /png_tensor/
      fi
  done

  # Write \x00 to start of each image file
  for filepath in /png_raw/*.png; do
      [ -e "$filepath" ] || continue
      filename=$(basename "$filepath")
      printf "\x00" | cat - "$filepath" > "/png_corpus/${filename}_input"
  done

  for filepath in /jpeg_raw/*.jp*g; do
      [ -e "$filepath" ] || continue
      filename=$(basename "$filepath")
      printf "\x00" | cat - "$filepath" > "/jpeg_corpus/${filename}_input"
  done
fi

done
