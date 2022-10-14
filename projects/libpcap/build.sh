#!/bin/bash -eu

cd /libpcap

FUZZ_TARGETS_DIR="testprogs/fuzz"

#Build targets for libfuzzer
echo "Build targets for libfuzzer."

CC="clang"
CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

mkdir libfuzzer && cd libfuzzer

../configure CC="$CC" CFLAGS="$CFLAGS"
make -j`nproc`

for target in pcap filter
do
        $CC $TARGET_CFLAGS -I ../ ../$FUZZ_TARGETS_DIR/fuzz_$target.c libpcap.a -o fuzz_$target 
done

make clean
cd /libpcap

#Build targets for afl++
echo "Build targets for afl++."

CC="afl-clang-fast"
CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

mkdir afl && cd afl

../configure CC="$CC" CFLAGS="$CFLAGS"
make -j`nproc`

for target in pcap filter
do
        $CC $TARGET_CFLAGS -I ../ ../$FUZZ_TARGETS_DIR/fuzz_$target.c libpcap.a -o fuzz_$target 
done

make clean
cd /libpcap

#Build targets for sydr
echo "Build targets for sydr."

cd /libpcap

CC="clang"
CFLAGS="-g"

mkdir sydr && cd sydr

../configure CC="$CC" CFLAGS="$CFLAGS"
make -j`nproc`

for target in pcap filter
do
        $CC $CFLAGS -I ../ ../load_sydr_$target.c libpcap.a -o load_sydr_$target 
done

make clean
cd /libpcap

#Build targets for cover
echo "Build targets for cover"

cd /libpcap

CC="clang"
CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

mkdir cover && cd cover

../configure CC="$CC" CFLAGS="$CFLAGS"
make -j`nproc`

for target in pcap filter
do
        $CC $CFLAGS -I ../ ../load_sydr_$target.c libpcap.a -o load_cover_$target 
done

cd /libpcap