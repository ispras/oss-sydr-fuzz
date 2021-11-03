#!/bin/bash -eu
# Copyright 2021 Google LLC
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

mkdir build
cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" -DCMAKE_CXX_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" ../
make "-j$(nproc)"
CC="clang"
CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
$CC $CFLAGS -I../src/lib/libdwarf/ \
  ../fuzz_init_path.c -o /fuzz_init_path ./src/lib/libdwarf/libdwarf.a

cd ..
rm -rf build
mkdir build
cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS="-g" -DCMAKE_CXX_FLAGS="-g" ../
make "-j$(nproc)"
CC="clang"
CFLAGS="-g"
$CC $CFLAGS -I../src/lib/libdwarf/ \
  ../fuzz_init_path_sydr.c -o /fuzz_init_path_sydr ./src/lib/libdwarf/libdwarf.a
