#!/bin/bash

set -u
set -e

# build targets for fuzzer
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_STATIC=1 -DENABLE_SHARED=0 \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
	-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero" \
	-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero" -DCMAKE_INSTALL_PREFIX=install
make "-j$(nproc)" "--load-average=$(nproc)"
make install

CXX=clang++
CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/compress.cc -o /compress_fuzzer \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/decompress.cc -o /decompress_fuzzer \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/transform.cc -o /transform_fuzzer \
    "install/lib/libturbojpeg.a"

# build targets for Sydr
cd ..
rm -rf build
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_STATIC=1 -DENABLE_SHARED=0 \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
	-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
	-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" -DCMAKE_INSTALL_PREFIX=install
make "-j$(nproc)" "--load-average=$(nproc)"
make install

CXX=clang++
CXXFLAGS="-g"
$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/compress_sydr.cc -o /compress_sydr \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/decompress_sydr.cc -o /decompress_sydr \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/transform_sydr.cc -o /transform_sydr \
    "install/lib/libturbojpeg.a"
