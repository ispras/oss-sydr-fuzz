#!/bin/bash -e
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

PATCH_HEADERS=$true

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
  export BUILD_SAVERS="ON"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
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
  export BUILD_SAVERS="OFF"
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
fi

# Build pytorch

cd /pytorch

# clean artifacts from previous build
python3 setup.py clean

MAX_JOBS=$(expr $(nproc) / 2) USE_FBGEMM=0 BUILD_BINARY=1 CC=$CC CXX=$CXX USE_STATIC_MKL=1 \
        USE_DISTRIBUTED=0 USE_MPI=0 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=1 BUILD_TEST=0 \
        BUILD_SHARED_LIBS=OFF USE_OPENMP=0 USE_MKLDNN=0 USE_ITT=0 \
        CXXFLAGS="$CXXFLAGS" CFLAGS="$CFLAGS" \
        CMAKE_THREAD_LIBS_INIT="$(find /usr/lib -name 'libpthread.so*' | head -1)" \
        python3 setup.py build

if [[ $PATCH_HEADERS ]]
then
  # Patch PyTorch headers to build torchvision with clang
  sed -i '1 i\#define ORDERED_DICT' /pytorch/torch/include/torch/csrc/api/include/torch/ordered_dict.h
  sed -i '1 i\#ifndef ORDERED_DICT' /pytorch/torch/include/torch/csrc/api/include/torch/ordered_dict.h
  echo "#endif" >> /pytorch/torch/include/torch/csrc/api/include/torch/ordered_dict.h

  sed -i '1 i\#define ORDERED_DICT' /pytorch/torch/csrc/api/include/torch/ordered_dict.h
  sed -i '1 i\#ifndef ORDERED_DICT' /pytorch/torch/csrc/api/include/torch/ordered_dict.h
  echo "#endif" >> /pytorch/torch/csrc/api/include/torch/ordered_dict.h

  sed -i '1 i\#define TYPES' /pytorch/torch/include/torch/csrc/api/include/torch/types.h
  sed -i '1 i\#ifndef TYPES' /pytorch/torch/include/torch/csrc/api/include/torch/types.h
  echo "#endif" >> /pytorch/torch/include/torch/csrc/api/include/torch/types.h

  sed -i '1 i\#define TYPES' /pytorch/torch/csrc/api/include/torch/types.h
  sed -i '1 i\#ifndef TYPES' /pytorch/torch/csrc/api/include/torch/types.h
  echo "#endif" >> /pytorch/torch/csrc/api/include/torch/types.h

  PATCH_HEADERS=$false
fi

# Build libpng

cd /libpng-1.6.37
rm -rf build
cmake -DCMAKE_C_COMPILER=$CC \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -S . -B build/
cd build
cmake --build . -j$(expr $(nproc) / 2)

# Build libjpeg-turbo

cd /libjpeg-turbo-2.1.3
rm -rf build
cmake -G"Unix Makefiles" -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DENABLE_STATIC=1 \
      -DENABLE_SHARED=0 -DWITH_JPEG8=1 \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -S . -B build/
cd build/
make -j$(expr $(nproc) / 2)

# Build zlib

cd /zlib
make clean
CC=$CC CXX=$CXX \
      CFLAGS="$CFLAGS" \
      CXXFLAGS="$CXXFLAGS" \
      ./configure
make -j$(expr $(nproc) / 2)

# Build ffmpeg

cd /ffmpeg
make clean
./configure --cc=$CC --cxx=$CXX
make -j$(expr $(nproc) / 2)

# Build torchvision

cd /vision
rm -rf build
Torch_DIR=/pytorch/ \
      cmake \
      -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DENGINE=$ENGINE -DSUFFIX=$SUFFIX -DBUILD_SAVERS=${BUILD_SAVERS:-} \
      -DJPEG_LIBRARY=/libjpeg-turbo-2.1.3/build/libjpeg.a \
      -DPNG_LIBRARY=/libpng-1.6.37/build/libpng.a \
      -DZLIB_LIBRARY=/zlib/libz.a \
      -DFFMPEG_DIR=/ffmpeg \
      -Donnx_LIBRARY=/pytorch/build/lib/libonnx.a \
      -Donnx_proto_LIBRARY=/pytorch/build/lib/libonnx_proto.a \
      -Dfoxi_loader_LIBRARY=/pytorch/build/lib/libfoxi_loader.a \
      -DCMAKE_C_COMPILER_ID=GNU -DCMAKE_CXX_COMPILER_ID=GNU \
      -S . -B build/
cd build/
cmake --build . -j$(expr $(nproc) / 2)
cmake --install .

if [[ $CONFIG = "sydr" ]]
then
  # Generate tensors from corpus
  
  cd /
  
  for filename in /jpeg_corpus/*; do 
      if ./save_jpeg "$filename"; then
          mv /jpeg_corpus/*.tensor /jpeg_tensor/
      fi
  done
  
  for filename in /png_corpus/*; do 
      if ./save_png "$filename"; then
          mv /png_corpus/*.tensor /png_tensor/
      fi
  done
  
  # Write \x00 to start of each image file
  for filename in /png_corpus/*.png; do
      [ -e "$filename" ] || continue
      printf "\x00" | cat - $filename > ${filename}_input
      rm $filename
  done
  
  for filename in /jpeg_corpus/*.jp*g; do
      [ -e "$filename" ] || continue
      printf "\x00" | cat - $filename > ${filename}_input
      rm $filename
  done
fi

done
