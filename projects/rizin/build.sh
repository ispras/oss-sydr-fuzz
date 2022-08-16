# Apply patches to support fuzzing
git apply --ignore-space-change --ignore-whitespace ./sydr-support-fuzzing.diff

# Build sydr binary
CURR_BUILD=sydr-plain
mkdir /$CURR_BUILD
CC=clang meson -Dfuzz_mode=sydr -Denable_tests=false -Denable_rz_test=false --default-library=static -Dstatic_runtime=false --buildtype=debugoptimized --prefix=/rizin-fuzzing/$CURR_BUILD build-$CURR_BUILD ; ninja -C build-$CURR_BUILD && ninja -C build-$CURR_BUILD install

# Build with AFL++ instrumentation + ASAN enabled
CURR_BUILD=afl-asan
mkdir /$CURR_BUILD
CC=afl-clang-lto CFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" meson -Dfuzz_mode=afl -Denable_tests=false -Denable_rz_test=false --default-library=static -Dstatic_runtime=false --buildtype=debugoptimized --prefix=/rizin-fuzzing/$CURR_BUILD build-$CURR_BUILD ; ninja -C build-$CURR_BUILD && ninja -C build-$CURR_BUILD install

# Coverage build
CURR_BUILD=coverage-plain
mkdir /$CURR_BUILD
# `fuzz_mode=sydr` is expected, in this mode we have default main
CC=clang CFLAGS="-O2 -fno-omit-frame-pointer -g -fprofile-instr-generate -fcoverage-mapping" meson -Dfuzz_mode=sydr -Denable_tests=false -Denable_rz_test=false --default-library=static -Dstatic_runtime=false --buildtype=debugoptimized --prefix=/rizin-fuzzing/$CURR_BUILD build-$CURR_BUILD ; ninja -C build-$CURR_BUILD && ninja -C build-$CURR_BUILD install
