# Copyright 2022 ISP RAS
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

#!/bin/bash

export CXX=clang++
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export CC=clang
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"

# build targets for fuzzer
cd /jpeg-9e/
./configure
make -j$(nproc)
make install

export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
$CXX $CXXFLAGS -std=c++11 /fuzz/jcompress_fuzzer.cc /jpeg-9e/rdgif.c /jpeg-9e/rdtarga.c \
    /jpeg-9e/rdbmp.c /jpeg-9e/rdppm.c /jpeg-9e/.libs/libjpeg.a -I /jpeg-9e -o /compress_fuzzer

# build targets for Sydr

export CXXFLAGS="-g"
export CFLAGS="-g"

make clean
./configure
make -j$(nproc)
make install

$CXX $CXXFLAGS -std=c++11 /fuzz/jcompress_sydr.cc /jpeg-9e/rdgif.c /jpeg-9e/rdtarga.c \
    /jpeg-9e/rdbmp.c /jpeg-9e/rdppm.c /jpeg-9e/.libs/libjpeg.a -I /jpeg-9e -o /compress_sydr

export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

make clean
./configure
make -j$(nproc)
make install

export LDFLAGS="-fprofile-instr-generate"

$CXX $CXXFLAGS -std=c++11 /fuzz/jcompress_sydr.cc /jpeg-9e/rdgif.c /jpeg-9e/rdtarga.c \
    /jpeg-9e/rdbmp.c /jpeg-9e/rdppm.c /jpeg-9e/.libs/libjpeg.a -I /jpeg-9e -o /compress_cov

