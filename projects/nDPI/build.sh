#!/bin/bash -eu

cd /nDPI

#Build targets for libfuzzer
echo "Build targets for libfuzzer."

export CC="clang"
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
INCLUDE_DIR="../src/include"
LIB_DIR="../src/lib/"

./autogen.sh
make -j`nproc`

mkdir libfuzzer && cd libfuzzer

$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I ../example ../fuzz/fuzz_ndpi_reader.c ../example/libndpiReader.a $LIB_DIR/libndpi.a -lpcap -o fuzz_ndpi_reader
$CC $TARGET_CFLAGS -I $INCLUDE_DIR ../fuzz/fuzz_process_packet.c $LIB_DIR/libndpi.a -o fuzz_process_packet

cd /nDPI
make clean

#Build targets for afl++
echo "Build targets for afl++."

export CC="afl-clang-fast"
export CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
export LDFLAGS="-fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
export AFL_LLVM_LAF_ALL=1
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

./autogen.sh
make -j`nproc`

mkdir afl && cd afl

$CC $TARGET_CFLAGS -I $INCLUDE_DIR -I ../example ../fuzz/fuzz_ndpi_reader.c ../example/libndpiReader.a $LIB_DIR/libndpi.a  -lpcap -o fuzz_ndpi_reader
$CC $TARGET_CFLAGS -I $INCLUDE_DIR ../fuzz/fuzz_process_packet.c $LIB_DIR/libndpi.a -o fuzz_process_packet

cd /nDPI
make clean
unset LDFLAGS

#Build targets for sydr
echo "Build targets for sydr."

export CC="clang"
export CFLAGS="-g"

./autogen.sh
make -j`nproc`

mkdir sydr && cd sydr

$CC $CFLAGS -I $INCLUDE_DIR -I ../example ../load_sydr_ndpi_reader.c ../example/libndpiReader.a $LIB_DIR/libndpi.a -lpcap -lm -o load_sydr_ndpi_reader
$CC $CFLAGS -I $INCLUDE_DIR ../load_sydr_process_packet.c $LIB_DIR/libndpi.a -lm -o load_sydr_process_packet

cd /nDPI
make clean

#Build targets for cover
echo "Build targets for cover"

export CC="clang"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

./autogen.sh
make -j`nproc`

mkdir cover && cd cover

$CC $CFLAGS -I $INCLUDE_DIR -I ../example ../load_sydr_ndpi_reader.c ../example/libndpiReader.a $LIB_DIR/libndpi.a  -lpcap -lm -o load_cover_ndpi_reader
$CC $CFLAGS -I $INCLUDE_DIR ../load_sydr_process_packet.c $LIB_DIR/libndpi.a -lm -o load_cover_process_packet

cd /nDPI