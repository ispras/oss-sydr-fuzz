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
    cd capstone$branch
    # build project
    mkdir build
    # does not seem to work in source directory
    # + make.sh overwrites CFLAGS
    cd build
    cmake -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero" -DCAPSTONE_BUILD_SHARED=0 ..
    make -j$(nproc)

    cd /capstone$branch/bindings/python
    #better debug info
    sed -i -e 's/#print/print/' capstone/__init__.py
    (
    export CFLAGS=""
    export AFL_NOOPT=1
    python setup.py install
    )
    cd /capstone$branch/suite
    mkdir fuzz/corpus
    find MC/ -name *.cs | ./test_corpus.py
    cd fuzz
    cp -r corpus /corpus$branch

    cd ../../build
    # build fuzz target
    CXX=clang++
    CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
    FUZZO=CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o
    if [ -f CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o ]; then
        FUZZO="$FUZZO CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o"
    fi
    $CXX $CXXFLAGS $FUZZO -o /fuzz_disasm$branch libcapstone.a

    # build Sydr target
    cd ..
    rm -rf build
    mkdir build
    cd build
    cmake -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS="-g" -DCAPSTONE_BUILD_SHARED=0 ..
    make -j$(nproc)
    FUZZO=../suite/fuzz/fuzz_harness.c
    if [ -f CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o ]; then
        FUZZO="$FUZZO CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o"
    fi
    clang -g $FUZZO -I../include/capstone -o /sydr_disasm$branch libcapstone.a

    cd ../../
done
