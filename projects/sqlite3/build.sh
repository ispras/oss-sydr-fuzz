#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

OUT="/sqlite3"
export CC=clang
export CXX=clang++

mkdir $OUT
mkdir bld
cd bld

export ASAN_OPTIONS="detect_leaks=0 halt_on_error=false"

# Limit max length of data blobs and sql queries to prevent irrelevant OOMs.
# Also limit max memory page count to avoid creating large databases.
export CFLAGS="-DSQLITE_MAX_LENGTH=128000000 \
               -DSQLITE_MAX_SQL_LENGTH=128000000 \
               -DSQLITE_MAX_MEMORY=25000000 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_DEBUG=1 \
               -DSQLITE_MAX_PAGE_COUNT=16384 \
               -g \
               -fsanitize=fuzzer-no-link,address,bounds,undefined,null,float-divide-by-zero"

export CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,undefined,null,float-divide-by-zero"

../configure
make -j$(nproc)
make sqlite3.c

$CC $CFLAGS -I. -c \
    ../test/ossfuzz.c -o ../test/ossfuzz.o

$CXX $CXXFLAGS \
    ../test/ossfuzz.o -pthread -ldl -o $OUT/ossfuzz \
    ./sqlite3.o

# Build fuzz target for Sydr
cd ..
rm -rf bld
mkdir bld
cd bld

export CFLAGS="-DSQLITE_MAX_LENGTH=128000000 \
               -DSQLITE_MAX_SQL_LENGTH=128000000 \
               -DSQLITE_MAX_MEMORY=25000000 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_DEBUG=1 \
               -DSQLITE_MAX_PAGE_COUNT=16384 \
               -g"
export CXXFLAGS="-g"

../configure
make -j$(nproc)
make sqlite3.c

$CC $CFLAGS -I. -c \
    ../test/sydrfuzz.c -o ../test/sydrfuzz.o

$CXX \
    ../test/sydrfuzz.o -pthread -ldl -o $OUT/sydrfuzz \
    ./sqlite3.o
