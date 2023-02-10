# Copyright 2023 ISP RAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

#!/bin/bash -eu

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
    $CC $TARGET_CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o libfuzzer/fuzz_$target
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
    $CC $TARGET_CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o afl++/fuzz_$target
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
    $CC $TARGET_CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o afl++-cmplog/fuzz_$target
done

make clean

unset AFL_LLVM_CMPLOG

#Build targets for afl++ with laf
echo "[x] Build targets for afl++ with laf."

export AFL_LLVM_LAF_ALL=1
CC="afl-clang-lto"
CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

./configure CC=$CC CFLAGS="$CFLAGS" --without-python --disable-shared
make -j$(nproc)

mkdir afl++-laf

for target in xml html regexp schema uri xinclude xpath
do
    $CC $TARGET_CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o afl++-laf/fuzz_$target
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
    $CC $CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $STANDALONE_MAIN $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o sydr/fuzz_$target
done

make clean

#Build targets for coverage
echo "[x] Build targets for coverage"

CC="clang"
CFLAGS="-fprofile-instr-generate -fcoverage-mapping -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

./configure CC=$CC CFLAGS="$CFLAGS" --without-python --disable-shared
make -j$(nproc)

mkdir cover

for target in xml html regexp schema uri xinclude xpath
do
    $CC $CFLAGS -I $INCLUDE_DIR -I $FUZZ_DIR $STANDALONE_MAIN $FUZZ_DIR/$target.c $FUZZ_DIR/fuzz.c $LIB_DIR -lz -llzma -lm -o cover/fuzz_$target
done

make clean
