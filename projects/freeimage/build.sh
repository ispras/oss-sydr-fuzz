#!/bin/bash -eu
# Copyright 2018 Google Inc.
# Modifications copyright (C) 2021 ISP RAS
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

# b44ExpLogTable.cpp only contains a definition of main().
sed -i 's/Source\/OpenEXR\/IlmImf\/b44ExpLogTable.cpp//' Makefile.srcs
INSTALL_DIR="Dist"


# Build targets for libFuzzer
export CXX="clang++"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
export CC="clang"
export CFLAGS=$CXXFLAGS
make -j$(nproc)

cd /
export CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
export CFLAGS=$CXXFLAGS
$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_fuzzer.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_fuzzer

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_tiff_fuzzer.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_tiff_fuzzer

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/ \
  transform_combined_jpeg_fuzzer.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /transform_combined_jpeg_fuzzer


# Build targets for Sydr
cd -
make clean
export CXX="clang++"
export CXXFLAGS="-g"
export CC="clang"
export CFLAGS=$CXXFLAGS
make -j$(nproc)

cd /
$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_sydr.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_sydr

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_tiff_sydr.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_tiff_sydr

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/ \
	transform_combined_jpeg_sydr.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
	-o /transform_combined_jpeg_sydr


# Build targets for AFL++
cd -
make clean
export CXX="afl-clang-fast++"
export CXXFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
export CC="afl-clang-fast"
export CFLAGS=$CXXFLAGS
make -j$(nproc)

cd /
export CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
export CFLAGS=$CXXFLAGS

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_fuzzer.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_afl

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_tiff_fuzzer.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_tiff_afl

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  transform_combined_jpeg_fuzzer.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /transform_combined_jpeg_afl


# Build targets for Honggfuzz
cd -
make clean
export CXX="hfuzz-clang++"
export CXXFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
export CC="hfuzz-clang"
export CFLAGS=$CXXFLAGS
make -j$(nproc)

cd /
$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_fuzzer.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_hfuzz

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_tiff_fuzzer.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_tiff_hfuzz

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  transform_combined_jpeg_fuzzer.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /transform_combined_jpeg_hfuzz


# Build targets for llvm-cov
cd -
make clean
export CXX="clang++"
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CC="clang"
export CFLAGS=$CXXFLAGS
make -j$(nproc)

cd /
$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_sydr.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_cov

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  load_from_memory_tiff_sydr.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /load_from_memory_tiff_cov

$CXX $CXXFLAGS -I/freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/  \
  transform_combined_jpeg_sydr.cc /freeimage-svn/FreeImage/trunk/${INSTALL_DIR}/libfreeimage.a \
  -o /transform_combined_jpeg_cov
