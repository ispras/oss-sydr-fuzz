#!/bin/bash

set -u
set -e

git apply /compress_yuv.patch
git apply /decompress_yuv.patch

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
    ../fuzz/compress_yuv.cc -o /compress_yuv_fuzzer \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/decompress.cc -o /decompress_fuzzer \
    "install/lib/libturbojpeg.a"
$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/decompress_yuv.cc -o /decompress_yuv_fuzzer \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/transform.cc -o /transform_fuzzer \
    "install/lib/libturbojpeg.a"

# build targets for AFL++
cd ..
rm -rf build
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_STATIC=1 -DENABLE_SHARED=0 \
        -DCMAKE_C_COMPILER=afl-clang-fast \
        -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
	-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero" \
	-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero" -DCMAKE_INSTALL_PREFIX=install
make "-j$(nproc)" "--load-average=$(nproc)"
make install

CXX=afl-clang-fast++
CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/afl.cc ../fuzz/compress.cc -o /compress_afl \
    "install/lib/libturbojpeg.a"
$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/afl.cc ../fuzz/compress_yuv.cc -o /compress_yuv_afl \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/afl.cc ../fuzz/decompress.cc -o /decompress_afl \
    "install/lib/libturbojpeg.a"
$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/afl.cc ../fuzz/decompress_yuv.cc -o /decompress_yuv_afl \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    ../fuzz/afl.cc ../fuzz/transform.cc -o /transform_afl \
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

CC=clang
CXX=clang++
CXXFLAGS="-g"

$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    main.o ../fuzz/compress.cc -o /compress_sydr \
    "install/lib/libturbojpeg.a"
$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    main.o ../fuzz/compress_yuv.cc -o /compress_yuv_sydr \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    main.o ../fuzz/decompress.cc -o /decompress_sydr \
    "install/lib/libturbojpeg.a"
$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    main.o ../fuzz/decompress_yuv.cc -o /decompress_yuv_sydr \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I.. -Iinstall/include \
    main.o ../fuzz/transform.cc -o /transform_sydr \
    "install/lib/libturbojpeg.a"

# build targets for llvm-cov
cd ..
rm -rf build
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_STATIC=1 -DENABLE_SHARED=0 \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
	-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG -fprofile-instr-generate -fcoverage-mapping" \
	-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG -fprofile-instr-generate -fcoverage-mapping" -DCMAKE_INSTALL_PREFIX=install
make "-j$(nproc)" "--load-average=$(nproc)"
make install

CC=clang
CXX=clang++
CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"

$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o

$CXX $CXXFLAGS -std=c++11 -I/libjpeg-turbo -I/libjpeg-turbo/build/install/include \
    main.o /libjpeg-turbo/fuzz/compress.cc -o /compress_cov \
    "install/lib/libturbojpeg.a"
$CXX $CXXFLAGS -std=c++11 -I/libjpeg-turbo -I/libjpeg-turbo/build/install/include \
    main.o /libjpeg-turbo/fuzz/compress_yuv.cc -o /compress_yuv_cov \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I/libjpeg-turbo -I/libjpeg-turbo/build/install/include \
    main.o /libjpeg-turbo/fuzz/decompress.cc -o /decompress_cov \
    "install/lib/libturbojpeg.a"
$CXX $CXXFLAGS -std=c++11 -I/libjpeg-turbo -I/libjpeg-turbo/build/install/include \
    main.o /libjpeg-turbo/fuzz/decompress_yuv.cc -o /decompress_yuv_cov \
    "install/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I/libjpeg-turbo -I/libjpeg-turbo/build/install/include \
    main.o /libjpeg-turbo/fuzz/transform.cc -o /transform_cov \
    "install/lib/libturbojpeg.a"
