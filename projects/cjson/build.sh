#!/bin/bash -eu

# This script is meant to be run by
# https://github.com/google/oss-fuzz/blob/master/projects/cjson/Dockerfile

mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
    ..
make -j$(nproc)

CC=clang
CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
$CC $CFLAGS /cjson/fuzzing/cjson_read_fuzzer.c -I. \
    -o /cjson_read_fuzzer \
    /cjson/build/libcjson.a

cd ..
rm -rf build
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_C_FLAGS=-g \
    ..
make -j$(nproc)

CC=clang
CFLAGS="-g"
$CC $CFLAGS /cjson/fuzzing/cjson_read_sydr.c -I. \
    -o /cjson_read_sydr \
    /cjson/build/libcjson.a
