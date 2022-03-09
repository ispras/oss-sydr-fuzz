#!/bin/bash -eu
# Copyright 2019 Google Inc.
# Modifications copyright (C) 2022 ISP RAS
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

#create zip files with initial corpus, taken from version control.
#for f in $(ls fuzzers/initial_corpus/) ;do
#  zip -j -r $OUT/fuzzer_${f}_seed_corpus.zip fuzzers/initial_corpus/$f
#done

mkdir build
cd build

# use C++ 14 instead of 17, because even if clang is
# bleeding edge, cmake is old in the oss fuzz image.

# Fuzzers
cmake .. \
-GNinja \
-DCMAKE_CXX_COMPILER=clang++ \
-DCMAKE_CXX_FLAGS="-g -fsanitize=fuzzer-no-link,address,undefined" \
-DCMAKE_EXE_LINKER_FLAGS="-lpthread" \
-DCMAKE_BUILD_TYPE=Debug \
-DCMAKE_CXX_STANDARD=14 \
-DFMT_DOC=Off \
-DFMT_TEST=Off \
-DFMT_SAFE_DURATION_CAST=On \
-DFMT_FUZZ=On \
-DFMT_FUZZ_LINKMAIN=Off \
-DFMT_FUZZ_LDFLAGS="$(find /usr/lib/clang -name libclang_rt.fuzzer-x86_64.a)"

CMAKE_BUILD_PARALLEL_LEVEL=6 cmake --build .

cp -r bin ../fuzzers

cd .. && rm -rf ./build && mkdir build && cd ./build

# Sydr
cmake .. \
-GNinja \
-DCMAKE_CXX_COMPILER=clang++ \
-DCMAKE_CXX_FLAGS="-g" \
-DCMAKE_EXE_LINKER_FLAGS="-lpthread" \
-DCMAKE_BUILD_TYPE=Debug \
-DCMAKE_CXX_STANDARD=14 \
-DFMT_DOC=Off \
-DFMT_TEST=Off \
-DFMT_SAFE_DURATION_CAST=On \
-DFMT_FUZZ=On \
-DFMT_FUZZ_LINKMAIN=ON

CMAKE_BUILD_PARALLEL_LEVEL=6 cmake --build .

cp -r bin ../sydr

cd .. && rm -rf ./build && mkdir build && cd ./build

# Coverage
cmake .. \
-GNinja \
-DCMAKE_CXX_COMPILER=clang++ \
-DCMAKE_CXX_FLAGS="-g -fprofile-instr-generate -fcoverage-mapping" \
-DCMAKE_EXE_LINKER_FLAGS="-lpthread -fprofile-instr-generate" \
-DCMAKE_BUILD_TYPE=Debug \
-DCMAKE_CXX_STANDARD=14 \
-DFMT_DOC=Off \
-DFMT_TEST=Off \
-DFMT_SAFE_DURATION_CAST=On \
-DFMT_FUZZ=On \
-DFMT_FUZZ_LINKMAIN=ON

CMAKE_BUILD_PARALLEL_LEVEL=6 cmake --build .

cp -r bin ../cov
