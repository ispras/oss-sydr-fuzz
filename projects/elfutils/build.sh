#!/bin/bash -eu

set -eux

export CC_FOR_BUILD=clang
export CXX_FOR_BUILD=clang++

export SRC=${SRC:-$(realpath -- $(dirname -- "$0"))}

cd "$SRC/elfutils"

git restore .

# ASan isn't compatible with -Wl,--no-undefined: https://github.com/google/sanitizers/issues/380
sed -i 's/^\(NO_UNDEFINED=\).*/\1/' configure.ac

# ASan isn't compatible with -Wl,-z,defs either:
# https://clang.llvm.org/docs/AddressSanitizer.html#usage
sed -i 's/^\(ZDEFS_LDFLAGS=\).*/\1/' configure.ac

# srcfiles.cxx started failing to compile with the OSS-Fuzz toolchain
# when it was switched from clang-18.0.0 to clang-18.1.8 in
# https://github.com/google/oss-fuzz/pull/12365.
# https://github.com/google/oss-fuzz/pull/12365#discussion_r1784702452
# It's probably an OSS-Fuzz toolchain bug but it doesn't matter much
# because the srcfiles binary isn't relevant in terms of fuzzing and
# can safely be excluded.
sed -i 's/^\(srcfiles_\)/#/' src/Makefile.am
sed -i 's/\bsrcfiles\b//' src/Makefile.am

# i386_gendis is only a build-time generator.
# Don't instrument it with UBSan.
sed -i '/^i386_parse\.o: i386_parse\.c i386\.mnemonics$/a\
i386_parse.o: CFLAGS += -fno-sanitize=undefined' libcpu/Makefile.am

if ! [[ -d "zlib" ]]; then
    git clone https://github.com/madler/zlib
fi

function flags() {
    unset CC CXX CFLAGS CXXFFLAGS LIB_FUZZING_ENGINE

    flags="-O1 -fno-omit-frame-pointer -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

    if (( $2 )); then
        flags+=" -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
        export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

        additional_ubsan_checks=alignment
        UBSAN_FLAGS="-fsanitize=$additional_ubsan_checks -fno-sanitize-recover=$additional_ubsan_checks"
        flags+=" $UBSAN_FLAGS"
    
        # That's basicaly what --enable-sanitize-undefined does to turn off unaligned access
        # elfutils heavily relies on on i386/x86_64 but without changing compiler flags along the way
        sed -i 's/\(check_undefined_val\)=[0-9]/\1=1/' configure.ac
    fi

    export CC=clang
    export CXX=clang++
    export CFLAGS=$flags
    export CXXFLAGS=$flags

    export OUT="$SRC/$1"
    mkdir -p "$OUT"
}

function build {
    $CC --version

    make distclean || true

    autoreconf -i -f
    if ! ./configure --enable-maintainer-mode --disable-debuginfod --disable-libdebuginfod \
                --disable-demangler --without-bzlib --without-lzma --without-zstd \
            CC="$CC" CFLAGS="-Wno-error $CFLAGS" CXX="$CXX" CXXFLAGS="-Wno-error $CXXFLAGS" LDFLAGS="$CFLAGS"; then
        cat config.log
        exit 1
    fi

    ASAN_OPTIONS=detect_leaks=0 make -j1 V=1

    pushd zlib
    make distclean || true
    git checkout v1.3.1
    if ! ./configure --static; then
        cat configure.log
        exit 1
    fi
    make -j$(nproc) V=1
    popd
    zlib=zlib/libz.a

    CFLAGS+=" -Werror -Wall -Wextra"
    CXXFLAGS+=" -Werror -Wall -Wextra"

    if ! [[ -n "${LIB_FUZZING_ENGINE:-}" ]]; then
        $CC $CFLAGS -c "$SRC/fuzz-main.c" -o "$OUT/fuzz-main.o"
        export LIB_FUZZING_ENGINE="$OUT/fuzz-main.o -pthread"
    fi

    # fuzz-dwfl-core is kind of a systemd fuzz target in the sense that it resembles the
    # code systemd uses to parse coredumps. Please ping @evverx if it's changed.
    $CC $CFLAGS \
        -D_GNU_SOURCE -DHAVE_CONFIG_H \
        -I. -I./lib -I./libelf -I./libebl -I./libdw -I./libdwelf -I./libdwfl -I./libasm \
        -c "$SRC/fuzz-dwfl-core.c" -o fuzz-dwfl-core.o
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-dwfl-core.o \
        ./libdw/libdw.a ./libelf/libelf.a ./lib/libeu.a "$zlib" \
        -o "$OUT/fuzz-dwfl-core"

    $CC $CFLAGS \
      -D_GNU_SOURCE -DHAVE_CONFIG_H \
      -I. -I./lib -I./libelf -I./libebl -I./libdw -I./libdwelf -I./libdwfl -I./libasm \
      -c "$SRC/fuzz-libelf.c" -o fuzz-libelf.o
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-libelf.o \
        ./libasm/libasm.a ./libebl/libebl.a ./backends/libebl_backends.a ./libcpu/libcpu.a \
      ./libdw/libdw.a ./libelf/libelf.a ./lib/libeu.a "$zlib" \
        -o "$OUT/fuzz-libelf"

    $CC $CFLAGS \
      -D_GNU_SOURCE -DHAVE_CONFIG_H \
      -I. -I./lib -I./libelf -I./libebl -I./libdw -I./libdwelf -I./libdwfl -I./libasm \
      -c "$SRC/fuzz-libdwfl.c" -o fuzz-libdwfl.o
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-libdwfl.o \
        ./libasm/libasm.a ./libebl/libebl.a ./backends/libebl_backends.a ./libcpu/libcpu.a \
      ./libdw/libdw.a ./libelf/libelf.a ./lib/libeu.a "$zlib" \
        -o "$OUT/fuzz-libdwfl"
}

# libfuzzer
flags libfuzzer 1
build

# afl++
flags aflpp 1

CC='afl-clang-fast'
CXX='afl-clang-fast++'
CFLAGS+=" -Wno-error=unused-function"
CXXFLAGS+=" -Wno-error=unused-function"

build 

unset CC 
unset CXX

# cov
flags cov 0

CFLAGS+=" -fprofile-instr-generate -fcoverage-mapping"
CXXFLAGS+=" -fprofile-instr-generate -fcoverage-mapping"

build

# sydr
flags sydr 0
build

