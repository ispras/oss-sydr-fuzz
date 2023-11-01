#!/bin/bash -eux
#
# Copyright 2017 Google Inc.
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

LLVM="/llvm-project/llvm"

if [[ $CONFIG = "libfuzzer" ]]
then
      export CC="clang"
      export CXX="clang++"
      export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
      export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
      export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
	    export SUFFIX="fuzz"
fi

if [[ $CONFIG = "afl" ]]
then
      export CC="afl-clang-fast"
      export CXX="afl-clang-fast++"
      export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
      export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
      export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
	    export SUFFIX="afl"
fi

if [[ $CONFIG = "sydr" ]]
then
      export CC=clang
      export CXX=clang++
      export CFLAGS="-g"
      export CXXFLAGS="$CFLAGS"
      export LINK_FLAGS="$CFLAGS"
	    export SUFFIX="sydr"
fi

if [[ $CONFIG = "coverage" ]]
then
      export CC=clang
      export CXX=clang++
      export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
      export CXXFLAGS="$CFLAGS"
      export LINK_FLAGS="$CFLAGS"
	    export SUFFIX="cov"
fi

cd llvm-project
rm -rf build
mkdir build
cd build

cmake -GNinja -DCMAKE_BUILD_TYPE=Release $LLVM \
    -DLLVM_ENABLE_PROJECTS="clang;lld;clang-tools-extra" \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;compiler-rt" \
    -DLLVM_ENABLE_ASSERTIONS=ON \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DLLVM_NO_DEAD_STRIP=ON \
    -DLLVM_EXPERIMENTAL_TARGETS_TO_BUILD=WebAssembly \
    -DCOMPILER_RT_INCLUDE_TESTS=OFF

for fuzzer in clang-fuzzer clang-format-fuzzer clang-objc-fuzzer clangd-fuzzer clang-pseudo-fuzzer llvm-itanium-demangle-fuzzer llvm-microsoft-demangle-fuzzer llvm-dwarfdump-fuzzer llvm-special-case-list-fuzzer;
do
  ninja $fuzzer
  cp bin/$fuzzer /
done

# 10th August 2022: The lines for building the dictionaries
# broke the whole build. They are left as a reminder to re-enable
# them once they have been fixed upstream.
#ninja clang-fuzzer-dictionary
#for fuzzer in "${CLANG_DICT_FUZZERS[@]}"; do
#  bin/clang-fuzzer-dictionary > $OUT/$fuzzer.dict
#done

#zip -j "/clang-objc-fuzzer_seed_corpus.zip"  $SRC/$LLVM/../clang/tools/clang-fuzzer/corpus_examples/objc/*
#zip -j "/clangd-fuzzer_seed_corpus.zip"  $SRC/$LLVM/../clang-tools-extra/clangd/test/*
