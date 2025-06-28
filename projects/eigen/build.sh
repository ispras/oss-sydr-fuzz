#!/bin/bash -eu
# Copyright 2019 Google Inc.
# Modifications copyright (C) 2025 ISP RAS
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

mkdir /corpus_basicstuff
mkdir /corpus_solver

# gen for libFuzzer

export CC=clang
export CXX=clang++
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined"
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined"

mkdir build_dir && cd build_dir
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS=$CXXFLAGS -DCMAKE_C_FLAGS=$CFLAGS ..
make install
cd ..

export CXXFLAGS="-g -fsanitize=fuzzer,address,undefined"
export CFLAGS="-g -fsanitize=fuzzer,address,undefined"

$CXX $CXXFLAGS -I. -Isrc/Eigen/Core /solver_fuzzer.cc -o /solver_fuzzer
$CXX $CXXFLAGS -I. -Isrc/Eigen/Core /basicstuff_fuzzer.cc -o /basicstuff_fuzzer

# gen for AFL++

export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CXXFLAGS="-g -fsanitize=address,undefined"
export CFLAGS="-g -fsanitize=address,undefined"

cd build_dir
make clean
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS=$CXXFLAGS -DCMAKE_C_FLAGS=$CFLAGS ..
make install
cd ..

export CXXFLAGS="-g -fsanitize=fuzzer,address,undefined"
export CFLAGS="-g -fsanitize=fuzzer,address,undefined"

$CXX $CXXFLAGS -I. -Isrc/Eigen/Core /solver_fuzzer.cc -o /solver_afl
$CXX $CXXFLAGS -I. -Isrc/Eigen/Core /basicstuff_fuzzer.cc -o /basicstuff_afl

# gen for Sydr

export CC=clang
export CXX=clang++
export CXXFLAGS="-g"
export CFLAGS="-g"

cd build_dir
make clean
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS=$CXXFLAGS -DCMAKE_C_FLAGS=$CFLAGS ..
make install
cd ..

$CC $CFLAGS -c /opt/StandaloneFuzzTargetMain.c -o /StandaloneFuzzTargetMain.o

$CXX $CXXFLAGS -I. -Isrc/Eigen/Core /StandaloneFuzzTargetMain.o /solver_fuzzer.cc -o /solver_sydr
$CXX $CXXFLAGS -I. -Isrc/Eigen/Core /StandaloneFuzzTargetMain.o /basicstuff_fuzzer.cc -o /basicstuff_sydr

# gen for coverage

export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

cd build_dir
make clean
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS=$CXXFLAGS -DCMAKE_C_FLAGS=$CFLAGS ..
make install
cd ..

$CC $CFLAGS -c /opt/StandaloneFuzzTargetMain.c -o /StandaloneFuzzTargetMain.o

$CXX $CXXFLAGS -I. -Isrc/Eigen/Core /StandaloneFuzzTargetMain.o /solver_fuzzer.cc -o /solver_cov
$CXX $CXXFLAGS -I. -Isrc/Eigen/Core /StandaloneFuzzTargetMain.o /basicstuff_fuzzer.cc -o /basicstuff_cov