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
fi

if [[ $CONFIG = "afl" ]]
then
  export SUFFIX="afl"
  export CC=afl-clang-fast
  export CXX=afl-clang-fast++
  export CFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow"
  export CXXFLAGS="-g -fsanitize=null,undefined,address,bounds,integer -fno-sanitize=pointer-overflow"
fi

if [[ $CONFIG = "sydr" ]]
then
  export SUFFIX="sydr"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g"
  export CXXFLAGS="-g"
fi

if [[ $CONFIG = "coverage" ]]
then
  export SUFFIX="cov"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g"
  export CXXFLAGS="-g"
fi

cd /pytorch_$SUFFIX

MAX_JOBS=$(nproc) USE_FBGEMM=0 BUILD_BINARY=1 CC=$CC CXX=$CXX USE_STATIC_MKL=1 \
        USE_DISTRIBUTED=0 USE_MPI=0 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=1 BUILD_TEST=0 \
        BUILD_SHARED_LIBS=OFF USE_OPENMP=0 USE_MKLDNN=0 \
        CXXFLAGS="$CXXFLAGS" CFLAGS="$CFLAGS" \
	CMAKE_THREAD_LIBS_INIT="$(find /usr/lib -name 'libpthread.so*' | head -1)" \
        python3 setup.py build

# Patch PyTorch headers to build torchvision with clang
sed -i '1 i\#define ORDERED_DICT' /pytorch_$SUFFIX/torch/include/torch/csrc/api/include/torch/ordered_dict.h
sed -i '1 i\#ifndef ORDERED_DICT' /pytorch_$SUFFIX/torch/include/torch/csrc/api/include/torch/ordered_dict.h
echo "#endif" >> /pytorch_$SUFFIX/torch/include/torch/csrc/api/include/torch/ordered_dict.h

sed -i '1 i\#define ORDERED_DICT' /pytorch_$SUFFIX/torch/csrc/api/include/torch/ordered_dict.h
sed -i '1 i\#ifndef ORDERED_DICT' /pytorch_$SUFFIX/torch/csrc/api/include/torch/ordered_dict.h
echo "#endif" >> /pytorch_$SUFFIX/torch/csrc/api/include/torch/ordered_dict.h


sed -i '1 i\#define TYPES' /pytorch_$SUFFIX/torch/include/torch/csrc/api/include/torch/types.h
sed -i '1 i\#ifndef TYPES' /pytorch_$SUFFIX/torch/include/torch/csrc/api/include/torch/types.h
echo "#endif" >> /pytorch_$SUFFIX/torch/include/torch/csrc/api/include/torch/types.h

sed -i '1 i\#define TYPES' /pytorch_$SUFFIX/torch/csrc/api/include/torch/types.h
sed -i '1 i\#ifndef TYPES' /pytorch_$SUFFIX/torch/csrc/api/include/torch/types.h
echo "#endif" >> /pytorch_$SUFFIX/torch/csrc/api/include/torch/types.h

done
