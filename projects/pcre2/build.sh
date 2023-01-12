echo '[x] Build target for libfuzzer'

CC="clang"
CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
TARGET_FLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

./autogen.sh
./configure CC=$CC CFLAGS="$CFLAGS" --enable-fuzz-support --enable-never-backslash-C --with-match-limit=1000 --with-match-limit-depth=1000
make -j$(nproc)

mkdir libfuzzer

$CC $TARGET_FLAGS -o libfuzzer/pcre2_fuzzer .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a

make clean

echo '[x] Build target for afl++'

export CC="afl-clang-lto"

./autogen.sh
./configure CC=$CC --enable-fuzz-support --enable-never-backslash-C --with-match-limit=1000 --with-match-limit-depth=1000
make -j$(nproc)

mkdir afl

$CC $TARGET_FLAGS -o afl/pcre2_fuzzer .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a

make clean

echo '[x] Build target for sydr'

CC="clang"
CFLAGS="-g"

./autogen.sh
./configure CC=$CC CFLAGS="$CFLAGS" --enable-fuzz-support --enable-never-backslash-C --with-match-limit=1000 --with-match-limit-depth=1000
make -j$(nproc)

mkdir sydr

$CC $CFLAGS -o sydr/pcre2_fuzzer /opt/StandaloneFuzzTargetMain.c .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a

make clean

echo '[x] Build target for cover'

CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

./autogen.sh
./configure CC=$CC CFLAGS="$CFLAGS" --enable-fuzz-support --enable-never-backslash-C --with-match-limit=1000 --with-match-limit-depth=1000
make -j$(nproc)

mkdir cover

$CC $CFLAGS -o cover/pcre2_fuzzer /opt/StandaloneFuzzTargetMain.c .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a

make clean
