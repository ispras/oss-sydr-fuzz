# Copyright 2024 ISP RAS
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

#!/bin/bash

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

make clean
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all NOISY_LOGGING=

export CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

for fuzzer_archive in ./src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS ./${fuzzer_name}.cc $fuzzer_archive -I ./src -I ./include -I ./brotli/c/dec -I ./brotli/c/common \
  -o ./targets/$fuzzer_name
done

# # Run fuzzing
# ./targets/convert_woff2ttf_fuzzer -close_fd_mask=3 ./corpus
# ./targets/convert_woff2ttf_fuzzer_new_entry -close_fd_mask=3 ./corpus

# Build targets for Sydr
export CFLAGS="-g"
export CXXFLAGS="-g"

make clean
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all NOISY_LOGGING=

for fuzzer_archive in ./src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS ./${fuzzer_name}_Sydr.cc $fuzzer_archive -I ./src -I ./include -I ./brotli/c/dec -I ./brotli/c/common \
  -o ./targets/${fuzzer_name}_Sydr
done

# # Run Sydr
# sydr-fuzz ./targets/convert_woff2ttf_fuzzer_Sydr @@ -l debug -j4 ./corpus
# sydr-fuzz ./targets/convert_woff2ttf_fuzzer_new_entry_Sydr @@ -l debug -j4 ./corpus

# Build targets for coverage
export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

make clean
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all NOISY_LOGGING=

for fuzzer_archive in ./src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS ./${fuzzer_name}_Sydr.cc $fuzzer_archive -I ./src -I ./include -I ./brotli/c/dec -I ./brotli/c/common \
  -o ./targets/${fuzzer_name}_cov
done

# # Getting coverage
# mkdir -p ./coverage/raw && cd ./coverage/raw
#
# for file in /src/woff2/corpus/*; do
#   LLVM_PROFILE_FILE=./$(basename "$file").profraw /src/woff2/targets/convert_woff2ttf_fuzzer_new_entry_cov "$file"
# done
#
# cd ../ && find raw/ > cov.lst
# llvm-profdata merge --input-files=cov.lst -o cov.profdata
#
# llvm-cov export /src/woff2/targets/convert_woff2ttf_fuzzer_cov -instr-profile cov.profdata -format=lcov > cov.lcov
# genhtml -o cov-html cov.lcov
# cp cov-html /fuzz -r

# Build targets for afl++
export CC="afl-clang-fast"
export CXX="afl-clang-fast++"
export CFLAGS="-g -O0 -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -std=c++11 -O0 -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"

make clean
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all NOISY_LOGGING=

for fuzzer_archive in ./src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS ./${fuzzer_name}_Sydr.cc $fuzzer_archive -I ./src -I ./include -I ./brotli/c/dec -I ./brotli/c/common \
  -o ./targets/${fuzzer_name}_afl
done

# # Run afl++ fuzzer
# AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 afl-fuzz -i ./corpus -o ./afl_output -D ./targets/convert_woff2ttf_fuzzer_afl @@
# AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 afl-fuzz -i ./corpus -o ./afl_output -D ./targets/convert_woff2ttf_fuzzer_new_entry_afl @@
