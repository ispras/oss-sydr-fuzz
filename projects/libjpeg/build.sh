#!/bin/bash

CXX=clang++
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
CC=clang
CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"

# build targets for fuzzer
cd /jpeg-9e/
./configure
make -j$(nproc)
make install

CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
$CXX $CXXFLAGS -std=c++11 /fuzz/jcompress_fuzzer.cc /jpeg-9e/rdgif.c /jpeg-9e/rdtarga.c \
    /jpeg-9e/rdbmp.c /jpeg-9e/rdppm.c /jpeg-9e/.libs/libjpeg.a -I /jpeg-9e -o /compress_fuzzer

# build targets for Sydr

CXXFLAGS="-g"
CFLAGS="-g"

make clean
./configure
make -j$(nproc)
make install

$CXX $CXXFLAGS -std=c++11 /fuzz/jcompress_sydr.cc /jpeg-9e/rdgif.c /jpeg-9e/rdtarga.c \
    /jpeg-9e/rdbmp.c /jpeg-9e/rdppm.c /jpeg-9e/.libs/libjpeg.a -I /jpeg-9e -o /compress_sydr

