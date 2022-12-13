#!/bin/bash -eu

cd /
tar -xvzf libpcap-1.9.1.tar.gz

export AFL_LLVM_LAF_ALL=1
export AFL_LLVM_DICT2FILE=/ndpi.dict

#Build targets for libfuzzer
echo "Build targets for libfuzzer."

export CC="clang"
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
INCLUDE_DIR="/nDPI/src/include"
LIB_DIR="/nDPI/src/lib/"

cd libpcap-1.9.1

./configure CC="$CC" CFLAGS="$CFLAGS" --disable-shared
make -j`nproc`
make install

cd /json-c && mkdir libfuzzer && cd libfuzzer
cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=$CC \
         -DCMAKE_C_FLAGS="$CFLAGS"
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .
make install

cd /nDPI

LDFLAGS="-lpcap" ./autogen.sh --with-only-libndpi
make -j`nproc`

mkdir libfuzzer && cd libfuzzer

$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I /nDPI/example /nDPI/fuzz/fuzz_ndpi_reader.c /nDPI/example/reader_util.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/libfuzzer/libjson-c.a -o fuzz_ndpi_reader
$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I /nDPI/example -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES /nDPI/fuzz/fuzz_ndpi_reader.c /nDPI/example/reader_util.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/libfuzzer/libjson-c.a -o fuzz_ndpi_reader_alloc_fail
$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I /nDPI/fuzz/ /nDPI/fuzz/fuzz_process_packet.c /nDPI/fuzz/fuzz_common_code.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/libfuzzer/libjson-c.a -o fuzz_process_packet
$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I /nDPI/fuzz/ /nDPI/fuzz/fuzz_quic_get_crypto_data.c /nDPI/fuzz/fuzz_common_code.c $LIB_DIR/libndpi.a /json-c/libfuzzer/libjson-c.a -o fuzz_quic_get_crypto_data

cp /nDPI/example/protos.txt /nDPI/example/categories.txt /nDPI/example/risky_domains.txt /nDPI/example/ja3_fingerprints.csv /nDPI/example/sha1_fingerprints.csv . 

cd /nDPI
make clean
cd /

#Build targets for afl++
echo "Build targets for afl++."

export CC="afl-clang-lto"
export CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

cd libpcap-1.9.1
make clean
./configure CC="$CC" CFLAGS="$CFLAGS" --disable-shared
make -j`nproc`
make install

cd /json-c && mkdir afl && cd afl
cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=$CC \
         -DCMAKE_C_FLAGS="$CFLAGS"
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .
make install

cd /nDPI

LDFLAGS="-lpcap"./autogen.sh --with-only-libndpi
make -j`nproc`

mkdir afl && cd afl

$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I /nDPI/example /nDPI/fuzz/fuzz_ndpi_reader.c /nDPI/example/reader_util.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/libfuzzer/libjson-c.a -o fuzz_ndpi_reader
$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I /nDPI/example -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES /nDPI/fuzz/fuzz_ndpi_reader.c /nDPI/example/reader_util.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/libfuzzer/libjson-c.a -o fuzz_ndpi_reader_alloc_fail
$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I /nDPI/fuzz/ /nDPI/fuzz/fuzz_process_packet.c /nDPI/fuzz/fuzz_common_code.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/libfuzzer/libjson-c.a -o fuzz_process_packet
$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I /nDPI/fuzz/ /nDPI/fuzz/fuzz_quic_get_crypto_data.c /nDPI/fuzz/fuzz_common_code.c $LIB_DIR/libndpi.a /json-c/libfuzzer/libjson-c.a -o fuzz_quic_get_crypto_data

cp /nDPI/example/protos.txt /nDPI/example/categories.txt /nDPI/example/risky_domains.txt /nDPI/example/ja3_fingerprints.csv /nDPI/example/sha1_fingerprints.csv . 

cd /nDPI
make clean
cd /

#Build targets for sydr
echo "Build targets for sydr."

export CC="clang"
export CFLAGS="-g"

cd libpcap-1.9.1
make clean
./configure CC="$CC" CFLAGS="$CFLAGS" --disable-shared
make -j`nproc`
make install

cd /json-c && mkdir sydr && cd sydr
cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=$CC \
         -DCMAKE_C_FLAGS="$CFLAGS"
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .
make install

cd /nDPI

LDFLAGS="-lpcap" ./autogen.sh --with-only-libndpi
make -j`nproc`

mkdir sydr && cd sydr

$CC $CFLAGS -I $INCLUDE_DIR -I /nDPI/example /nDPI/load_sydr_ndpi_reader.c /nDPI/example/reader_util.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/sydr/libjson-c.a -lm -o load_sydr_ndpi_reader
$CC $CFLAGS -I $INCLUDE_DIR -I /nDPI/example -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES /nDPI/load_sydr_ndpi_reader.c /nDPI/example/reader_util.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/sydr/libjson-c.a -lm -o load_sydr_ndpi_reader_alloc_fail
$CC $CFLAGS -I $INCLUDE_DIR -I /nDPI/fuzz/ /nDPI/load_sydr_process_packet.c /nDPI/fuzz/fuzz_common_code.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/sydr/libjson-c.a -lm -o load_sydr_process_packet
$CC $CFLAGS -I $INCLUDE_DIR -I /nDPI/fuzz/ /nDPI/load_sydr_quic_get_crypto_data.c /nDPI/fuzz/fuzz_common_code.c $LIB_DIR/libndpi.a /json-c/sydr/libjson-c.a -lm -o load_sydr_quic_get_crypto_data

cp /nDPI/example/protos.txt /nDPI/example/categories.txt /nDPI/example/risky_domains.txt /nDPI/example/ja3_fingerprints.csv /nDPI/example/sha1_fingerprints.csv .

cd /nDPI
make clean
cd /

#Build targets for cover
echo "Build targets for cover"

export CC="clang"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

cd libpcap-1.9.1
make clean
./configure CC="$CC" CFLAGS="$CFLAGS" --disable-shared
make -j`nproc`
make install

cd /json-c && mkdir cover && cd cover
cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=$CC \
         -DCMAKE_C_FLAGS="$CFLAGS"
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .
make install

cd /nDPI

LDFLAGS="-lpcap" ./autogen.sh --with-only-libndpi
make -j`nproc`

mkdir cover && cd cover

$CC $CFLAGS -I $INCLUDE_DIR -I /nDPI/example /nDPI/load_sydr_ndpi_reader.c /nDPI/example/reader_util.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/cover/libjson-c.a -lm -o load_cover_ndpi_reader
$CC $CFLAGS -I $INCLUDE_DIR -I /nDPI/example -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES /nDPI/load_sydr_ndpi_reader.c /nDPI/example/reader_util.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/cover/libjson-c.a -lm -o load_cover_ndpi_reader_alloc_fail
$CC $CFLAGS -I $INCLUDE_DIR -I /nDPI/fuzz/ /nDPI/load_sydr_process_packet.c /nDPI/fuzz/fuzz_common_code.c $LIB_DIR/libndpi.a /libpcap-1.9.1/libpcap.a /json-c/cover/libjson-c.a -lm -o load_cover_process_packet
$CC $CFLAGS -I $INCLUDE_DIR -I /nDPI/fuzz/ /nDPI/load_sydr_quic_get_crypto_data.c /nDPI/fuzz/fuzz_common_code.c $LIB_DIR/libndpi.a /json-c/sydr/libjson-c.a -lm -o load_cover_quic_get_crypto_data

cp /nDPI/example/protos.txt /nDPI/example/categories.txt /nDPI/example/risky_domains.txt /nDPI/example/ja3_fingerprints.csv /nDPI/example/sha1_fingerprints.csv .

cd /nDPI
