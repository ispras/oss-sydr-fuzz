#!/bin/bash -eu
# Copyright 2018 Google Inc.
# Modifications copyright (C) 2021 ISP RAS
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

#add next branch
for branch in v4 next
do
    cd /capstone$branch

    # Build libFuzzer target
    mkdir build && cd build
    # does not seem to work in source directory
    # + make.sh overwrites CFLAGS
    cmake -DCMAKE_C_COMPILER=clang \
          -DCMAKE_CXX_COMPILER=clang++ \
          -DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero" \
          -DCMAKE_CXX_FLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero" \
          -DCAPSTONE_BUILD_SHARED=0 \
          ..
    make -j$(nproc)
    FUZZO=CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o
    if [ -f CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o ]; then
        FUZZO="$FUZZO CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o"
    fi
    clang++ -g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero $FUZZO -I../include/capstone -o /fuzz_disasm$branch libcapstone.a


    # Build AFL++ target
    cd .. && rm -rf build && mkdir build && cd build
    cmake -DCMAKE_C_COMPILER=afl-clang-fast \
          -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
          -DCMAKE_C_FLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero" \
          -DCMAKE_CXX_FLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero" \
          -DCAPSTONE_BUILD_SHARED=0 \
          ..
    make -j$(nproc)
    FUZZO=CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o
    if [ -f CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o ]; then
        FUZZO="$FUZZO CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o"
    fi
    afl-clang-fast++ -g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero $FUZZO -I../include/capstone -o /afl_disasm$branch libcapstone.a


    # Build Sydr target
    cd .. && rm -rf build && mkdir build && cd build
    cmake -DCMAKE_C_COMPILER=clang \
          -DCMAKE_CXX_COMPILER=clang++ \
          -DCMAKE_C_FLAGS="-g" \
          -DCMAKE_CXX_FLAGS="-g" \
          -DCAPSTONE_BUILD_SHARED=0 \
          ..
    make -j$(nproc)
    FUZZO=../suite/fuzz/fuzz_harness.c
    if [ -f CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o ]; then
        FUZZO="$FUZZO CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o"
    fi
    clang -g $FUZZO -I../include/capstone -o /sydr_disasm$branch libcapstone.a


    # Build cov target
    cd .. && rm -rf build && mkdir build && cd build
    cmake -DCMAKE_C_COMPILER=clang \
          -DCMAKE_CXX_COMPILER=clang++ \
          -DCMAKE_C_FLAGS="-g -fprofile-instr-generate -fcoverage-mapping" \
          -DCMAKE_CXX_FLAGS="-g -fprofile-instr-generate -fcoverage-mapping" \
          -DCAPSTONE_BUILD_SHARED=0 \
          ..
    make -j$(nproc)
    FUZZO=../suite/fuzz/fuzz_harness.c
    if [ -f CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o ]; then
        FUZZO="$FUZZO CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o"
    fi
    clang -g -fprofile-instr-generate -fcoverage-mapping $FUZZO -I../include/capstone -o /cov_disasm$branch libcapstone.a


    # Prepare corpus
    cd ../bindings/python
    (export CFLAGS="" && python setup.py install)
    cd ../../suite
    mkdir fuzz/corpus
    find MC/ -name *.cs | ./test_corpus.py
    cp -r fuzz/corpus /corpus$branch

done
