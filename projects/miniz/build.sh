#!/bin/bash -eu
# Copyright 2020 Google Inc.
# Modifications copyright (C) 2022 ISP RAS
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

# Build Fuzz targets.
mkdir /fuzzers
mkdir build
cd build
cmake .. -DAMALGAMATE_SOURCES=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_FUZZERS=ON  \
-DCMAKE_C_COMPILER=clang \
-DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
make -j$(nproc)
cd ..

CC="clang"
CFLAGS="-g -fsanitize=fuzzer,address,undefined"

for f in $(find . -name '*_fuzzer.c'); do
    b=$(basename -s .c $f)
    $CC $CFLAGS -Ibuild/amalgamation $f -c -o /tmp/$b.o
    $CC $CFLAGS -Ibuild/amalgamation /tmp/$b.o -o /fuzzers/$b  ./build/libminiz.a
    rm -f /tmp/$b.o
done

cp tests/zip.dict /zip_fuzzer.dict

# Build Sydr targets.
mkdir /sydr
rm -rf build && mkdir build
cd build
cmake .. -DAMALGAMATE_SOURCES=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_FUZZERS=ON  \
-DCMAKE_C_COMPILER=clang \
-DCMAKE_C_FLAGS="-g"
make -j$(nproc)

for f in $(find ../bin -name '*_fuzzer'); do
    b=$(basename -s _fuzzer $f)
    cp $f /sydr/$b\_sydr
done
