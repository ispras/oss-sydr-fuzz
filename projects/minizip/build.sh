#!/bin/bash 
# Copyright 2018 Google Inc.
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

# Force static linking in i386 by removing dynamically linked libraries.
if [ "$ARCHITECTURE" = 'i386' ]; then
  rm /usr/lib/i386-linux-gnu/libssl.so*
  rm /usr/lib/i386-linux-gnu/libcrypto.so*
fi

# Build project
export CC=clang
export CXX=clang++ 
export CFLAGS="-fsanitize=fuzzer-no-link,address,undefined"
export CXXFLAGS="-fsanitize=fuzzer-no-link,address,undefined"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
cmake . -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DMZ_BUILD_FUZZ_TESTS=ON
make clean
make -j$(nproc)

# Copy the fuzzer executables, zip-ed corpora, and dictionary files to /
find . -name '*_fuzzer' -exec cp -v '{}' / ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' / ';'
find . -name '*_fuzzer.c' -exec cp -v '{}' / ';'

#build sydr

export CXXFLAGS="-g"
export CFLAGS="-g"

make clean
make -j$(nproc)

$CC $CXXFLAGS -std=c17 /unzip_fuzzer.c ./test/fuzz/standalone.c ./mz_strm_os_posix.c \
                      ./mz_crypt.c  ./mz_strm.c ./mz_strm_mem.c ./mz_zip.c -I . -o /unzip_sydr
$CC $CXXFLAGS -std=c17 /zip_fuzzer.c ./test/fuzz/standalone.c ./mz_strm_os_posix.c \
                      ./mz_crypt.c  ./mz_strm.c ./mz_strm_mem.c ./mz_zip.c -I . -o /zip_sydr

#build cov
export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

make clean
make -j$(nproc)

$CC $CXXFLAGS -std=c17 /unzip_fuzzer.c ./test/fuzz/standalone.c ./mz_strm_os_posix.c ./mz_crypt.c \
                      ./mz_strm.c ./mz_strm_mem.c ./mz_zip.c -I . -o /unzip_cov
$CC $CXXFLAGS -std=c17 /zip_fuzzer.c ./test/fuzz/standalone.c ./mz_strm_os_posix.c ./mz_crypt.c  \
                      ./mz_strm.c ./mz_strm_mem.c ./mz_zip.c -I . -o /zip_cov


