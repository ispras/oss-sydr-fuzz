#!/bin/bash -eu
# Copyright 2016 Google Inc.
# Modifications copyright (C) 2024 ISP RAS
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

export CC=clang
export CXX=clang++
export SRC=.

# Build the library. Actually there is no 'library' target, so we use .o files.
# '-no-canonical-prefixes' flag makes clang crazy. Need to avoid it.
cat brotli/shared.mk | sed -e "s/-no-canonical-prefixes//" > brotli/shared.mk.temp
mv brotli/shared.mk.temp brotli/shared.mk

# Build targets for fuzzing
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"

make clean -j$(nproc)
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all NOISY_LOGGING= -j$(nproc)

export CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

for fuzzer_archive in ./src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS ./src/${fuzzer_name}.cc $fuzzer_archive \
  -I ./src -I ./include -I ./brotli/c/dec -I ./brotli/c/common \
  -o ./targets/$fuzzer_name
done

# Build targets for Sydr
export CFLAGS="-g"
export CXXFLAGS="-g"

make clean -j$(nproc)
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all NOISY_LOGGING= -j$(nproc)

${CC} $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o /opt/StandaloneFuzzTargetMain.o

for fuzzer_archive in ./src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS ./src/${fuzzer_name}.cc  /opt/StandaloneFuzzTargetMain.o $fuzzer_archive \
  -I ./src -I ./include -I ./brotli/c/dec -I ./brotli/c/common \
  -o ./targets/${fuzzer_name}_Sydr
done

# Build targets for coverage
export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

make clean -j$(nproc)
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all NOISY_LOGGING= -j$(nproc)

${CC} $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o /opt/StandaloneFuzzTargetMain.o

for fuzzer_archive in ./src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS ./src/${fuzzer_name}.cc  /opt/StandaloneFuzzTargetMain.o $fuzzer_archive \
  -I ./src -I ./include -I ./brotli/c/dec -I ./brotli/c/common \
  -o ./targets/${fuzzer_name}_cov
done

# Build targets for afl++
export CC="afl-clang-fast"
export CXX="afl-clang-fast++"
export CFLAGS="-g -O0 -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -std=c++11 -O0 -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"

make clean -j$(nproc)
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all NOISY_LOGGING= -j$(nproc)

export CFLAGS="-g -O0 -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -std=c++11 -O0 -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

${CC} $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o /opt/StandaloneFuzzTargetMain.o

for fuzzer_archive in ./src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS ./src/${fuzzer_name}.cc /opt/StandaloneFuzzTargetMain.o $fuzzer_archive \
  -I ./src -I ./include -I ./brotli/c/dec -I ./brotli/c/common \
  -o ./targets/${fuzzer_name}_afl
done
