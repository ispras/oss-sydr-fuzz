#!/usr/bin/env bash

# Copyright 2021 Google LLC
# Modifications copyright (C) 2026 ISP RAS
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

set -eux

# fuzz-dwfl-core is kind of a systemd fuzz target in the sense that it resembles the
# code systemd uses to parse coredumps. Please ping @evverx if it's changed.
function dwfl-core() {
    $CC $CFLAGS \
        -D_GNU_SOURCE -DHAVE_CONFIG_H \
        -I. -I./lib -I./libelf -I./libebl -I./libdw -I./libdwelf -I./libdwfl -I./libasm \
        -c "$FUZZ_DIR/fuzz-dwfl-core.c" -o fuzz-dwfl-core.o
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-dwfl-core.o \
        ./libdw/libdw.a ./libelf/libelf.a ./lib/libeu.a "$zlib" \
        -o "$OUT/fuzz-dwfl-core"
}

function libelf() {
    $CC $CFLAGS \
      -D_GNU_SOURCE -DHAVE_CONFIG_H \
      -I. -I./lib -I./libelf -I./libebl -I./libdw -I./libdwelf -I./libdwfl -I./libasm \
      -c "$FUZZ_DIR/fuzz-libelf.c" -o fuzz-libelf.o
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-libelf.o \
        ./libasm/libasm.a ./libebl/libebl.a ./backends/libebl_backends.a ./libcpu/libcpu.a \
      ./libdw/libdw.a ./libelf/libelf.a ./lib/libeu.a "$zlib" \
        -o "$OUT/fuzz-libelf"
}

function libdwfl() {
    $CC $CFLAGS \
      -D_GNU_SOURCE -DHAVE_CONFIG_H \
      -I. -I./lib -I./libelf -I./libebl -I./libdw -I./libdwelf -I./libdwfl -I./libasm \
      -c "$FUZZ_DIR/fuzz-libdwfl.c" -o fuzz-libdwfl.o
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-libdwfl.o \
        ./libasm/libasm.a ./libebl/libebl.a ./backends/libebl_backends.a ./libcpu/libcpu.a \
      ./libdw/libdw.a ./libelf/libelf.a ./lib/libeu.a "$zlib" \
        -o "$OUT/fuzz-libdwfl"
}

# 
# SET FLAGS
#
if [[ $TARGET = "libfuzzer" ]]
then
  export SUFFIX=${SUFFIX:-"libfuzzer"}
  export CC=${CC:-clang}
  export CXX=${CXX:-clang++}
  export CFLAGS+=" -g -fsanitize=fuzzer-no-link,address,undefined,bounds,null,float-divide-by-zero -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  export CXXFLAGS+=" -g -fsanitize=fuzzer-no-link,address,undefined,bounds,null,float-divide-by-zero -std=c++20 -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  export ENGINE=${ENGINE:-"$(find $(llvm-config --libdir) -name libclang_rt.fuzzer-x86_64.a | head -1)"}
fi

if [[ $TARGET = "aflpp" ]]
then
  export SUFFIX=${SUFFIX:-"aflpp"}
  export CC=${CC:-afl-clang-fast}
  export CXX=${CXX:-afl-clang-fast++}
  export CFLAGS+=" -g -fsanitize=address,undefined,bounds,null,float-divide-by-zero -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  export CXXFLAGS+=" -g -fsanitize=address,undefined,bounds,null,float-divide-by-zero -std=c++20 -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  export ENGINE=${ENGINE:-"$(find /usr/local/ -name 'libAFLDriver.a' | head -1)"}
fi

if [[ $TARGET = "sydr" ]]
then
  export SUFFIX=${SUFFIX:-"sydr"}
  export CC=${CC:-clang}
  export CXX=${CXX:-clang++}
  export CFLAGS+=" -g -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  export CXXFLAGS+=" -g -std=c++20 -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  export ENGINE=${ENGINE:-"/StandaloneFuzzTargetMain.o"}
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
fi

if [[ $TARGET = "cov" ]]
then
  export SUFFIX=${SUFFIX:-"cov"}
  export CC=${CC:-clang}
  export CXX=${CXX:-clang++}
  export CFLAGS+=" -g -fprofile-instr-generate -fcoverage-mapping -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  export CXXFLAGS+=" -g -fprofile-instr-generate -fcoverage-mapping -std=c++20 -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  export ENGINE=${ENGINE:-"/StandaloneFuzzTargetMain.o"}
  $CC $CFLAGS -c -o $ENGINE /opt/StandaloneFuzzTargetMain.c
fi
export RESET=${RESET:-1}
export SRC=${SRC:-"$RESULT_DIR/elfutils"}
export OUT=${OUT:-"$RESULT_FUZZ_DIR/$SUFFIX"}

#
# STARTING 
#
cd $SRC
mkdir -p "$OUT"

#
# RESET
#
if (( $RESET )); then
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

    # That's basicaly what --enable-sanitize-undefined does to turn off unaligned access
    # elfutils heavily relies on on i386/x86_64 but without changing compiler flags along the way
    sed -i 's/\(check_undefined_val\)=[0-9]/\1=1/' configure.ac

    if ! [[ -d "zlib" ]]; then
        git clone https://github.com/madler/zlib
    fi

    make distclean || true

    autoreconf -i -f
    if ! ./configure --enable-maintainer-mode --disable-debuginfod --disable-libdebuginfod \
                --disable-demangler --without-bzlib --without-lzma --without-zstd \
            CC="$CC" CFLAGS="-Wno-error $CFLAGS" CXX="$CXX" CXXFLAGS="-Wno-error $CXXFLAGS" LDFLAGS="$CFLAGS"; then
        cat config.log
        exit 1
    fi

    pushd zlib
    make distclean || true
    git checkout v1.3.1
    if ! ./configure --static; then
        cat configure.log
        exit 1
    fi
    popd
fi

#
# BUILD
#
ASAN_OPTIONS=detect_leaks=0 make -j$(nproc) V=1

pushd zlib
make -j$(nproc) V=1
popd
zlib=zlib/libz.a

export LIB_FUZZING_ENGINE="$ENGINE -pthread"

case "$1" in
    all)
        dwfl-core
        libdwfl
        libelf
        ;;
    dwfl-core) 
        dwfl-core
        ;;
    libdwfl) 
        libdwfl
        ;;
    libelf) 
        libelf
        ;;
    *)
        echo "invalid build target";
        exit 1
    ;;
esac
