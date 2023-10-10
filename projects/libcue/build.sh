#!/bin/bash -eu

cd /libcue

sed -i 's/<<EOF>>>/<<EOF>>/g' cue_scanner.l

mkdir afl && cd afl

CC=afl-clang-lto
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

export AFL_LLVM_DICT2FILE=/libcue.dict
cmake -DCMAKE_C_COMPILER=$CC \
	-DCMAKE_C_FLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" \
	..
make -j$(nproc)

$CC $TARGET_CFLAGS -I/libcue /fuzz_cue_parse_string.c libcue.a -o fuzz_cue_parse_string

cd ..

mkdir libfuzzer && cd libfuzzer

CC=clang
cmake .. -DCMAKE_C_COMPILER=$CC \
	-DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
	..
make -j$(nproc)

$CC $TARGET_CFLAGS -I/libcue /fuzz_cue_parse_string.c libcue.a -o fuzz_cue_parse_string

cd ..

mkdir cover && cd cover

TARGET_CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

cmake .. -DCMAKE_C_COMPILER=$CC \
	-DCMAKE_C_FLAGS="$TARGET_CFLAGS" \
	..
make -j$(nproc)

$CC $TARGET_CFLAGS -I/libcue /opt/StandaloneFuzzTargetMain.c /fuzz_cue_parse_string.c libcue.a -o fuzz_cue_parse_string

cd ..

mkdir sydr && cd sydr

TARGET_CFLAGS="-g"

cmake .. -DCMAKE_C_COMPILER=$CC \
	-DCMAKE_C_FLAGS="$TARGET_CFLAGS" \
	..
make -j$(nproc)

$CC $TARGET_CFLAGS -I/libcue /opt/StandaloneFuzzTargetMain.c /fuzz_cue_parse_string.c libcue.a -o fuzz_cue_parse_string

cd .. && mkdir /corpus && cp t/*.cue /corpus
