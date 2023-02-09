#!/bin/bash -eu

cd /libxml2/

INCLUDE_DIR="/libxml2/include/"
FUZZ_DIR="/libxml2/fuzz/"
LIB_DIR="/libxml2/.libs/libxml2.a"
STANDALONE_MAIN="/opt/StandaloneFuzzTargetMain.c"

export AFL_LLVM_DICT2FILE=/libxml2.dict

./autogen.sh

autoconf -f

#Build targets for libfuzzer
echo "[x] Build targets for libfuzzer."

CC="clang"
CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

./configure CC=$CC CFLAGS="$CFLAGS" --without-python --disable-shared
make -j$(nproc)

mkdir libfuzzer

for target in xml html regexp schema uri xinclude xpath
do
    clang $TARGET_CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o libfuzzer/fuzz_$target
done

make clean

#Build targets for afl++
echo "[x] Build targets for afl++."

CC="afl-clang-lto"
CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

./configure CC=$CC CFLAGS="$CFLAGS" --without-python --disable-shared
make -j$(nproc)

mkdir afl++

for target in xml html regexp schema uri xinclude xpath
do
    afl-clang-lto $TARGET_CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o afl++/fuzz_$target
done

make clean

#Build targets for afl++ with cmplog
echo "[x] Build targets for afl++ with cmplog."

export AFL_LLVM_CMPLOG=1
CC="afl-clang-lto"
CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

./configure CC=$CC CFLAGS="$CFLAGS" --without-python --disable-shared
make -j$(nproc)

mkdir afl++-cmplog

for target in xml html regexp schema uri xinclude xpath
do
    afl-clang-lto $TARGET_CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o afl++-cmplog/fuzz_$target
done

make clean

#Build targets for sydr
echo "[x] Build targets for sydr."

CC="clang"
CFLAGS="-g"

./configure CC=$CC CFLAGS="$CFLAGS" --without-python --disable-shared
make -j$(nproc)

mkdir sydr

for target in xml html regexp schema uri xinclude xpath
do
    clang $CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $STANDALONE_MAIN $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o sydr/fuzz_$target
done

make clean

#Build targets for cover
echo "[x] Build targets for cover"

CC="clang"
CFLAGS="-fprofile-instr-generate -fcoverage-mapping -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

./configure CC=$CC CFLAGS="$CFLAGS" --without-python --disable-shared
make -j$(nproc)

mkdir cover

for target in xml html regexp schema uri xinclude xpath
do
    clang $CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $STANDALONE_MAIN $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o cover/fuzz_$target
done

make clean
