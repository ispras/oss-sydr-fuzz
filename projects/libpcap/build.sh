#!/bin/bash -eu

#build target for libfuzzer
echo "Build target for libfuzzer."

mkdir libfuzzer && cd libfuzzer

../configure CC=clang CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
	LDFLAGS="-fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
make -j`nproc`

clang -g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero -I ../ \
	../testprogs/fuzz/fuzz_both.c libpcap.a -o load_fuzz

cd ../

#build target for sydr
echo "Build target for sydr."

mkdir dse && cd dse

../configure CC=clang CFLAGS="-g"

make -j`nproc` 

clang -g -I ../ ../load_sydr.c libpcap.a -o load_sydr

cd ../

#build target to collect coverage
echo "Build target to collect coverage."

mkdir cover && cd cover

../configure CC=clang CFLAGS="-fprofile-instr-generate -fcoverage-mapping" \
	LDFLAGS="-fprofile-instr-generate"

make -j`nproc` 

clang -fprofile-instr-generate -fcoverage-mapping -I ../ ../load_sydr.c libpcap.a -o load_cover
