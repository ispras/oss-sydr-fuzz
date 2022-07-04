#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# First, build RE2.
# N.B., we don't follow the standard incantation for building RE2
# (i.e., `make && make test && make install && make testinstall`),
# because some of the targets doesn't use $CXXFLAGS properly, which
# causes compilation to fail. The obj/libre2.a target is all we
# really need for our fuzzer, so that's all we build. Hopefully
# this won't cause the fuzzer to fail erroneously due to not running
# upstream's tests first to be sure things compiled correctly.
mkdir /re2_fuzzer
make clean
make CXX=clang++ CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" -j$(nproc) obj/libre2.a

CXX=clang++
CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
# Second, build the fuzzer (distributed with RE2).
$CXX $CXXFLAGS -std=c++11 -I. -Ire2/fuzzing/compiler-rt/include/ \
	re2/fuzzing/re2_fuzzer.cc -o /re2_fuzzer/re2_fuzzer \
	obj/libre2.a

mkdir /re2_afl
make clean
make CXX=afl-clang-fast++ CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" -j$(nproc) obj/libre2.a

CXX=afl-clang-fast++
CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"

$CXX $CXXFLAGS -o /afl.o -c /afl.cc

# Second, build the fuzzer (distributed with RE2).
$CXX $CXXFLAGS -std=c++11 -I. -Ire2/fuzzing/compiler-rt/include/ \
	re2/fuzzing/re2_fuzzer.cc -o /re2_afl/re2_afl \
	/afl.o obj/libre2.a

mkdir /re2_sydr
make clean
make CXX=clang++ CXXFLAGS="-O2 -fno-omit-frame-pointer -g" -j$(nproc) obj/libre2.a

CXX=clang++
CXXFLAGS="-O2 -fno-omit-frame-pointer -g"
# Second, build the fuzzer (distributed with RE2).
$CXX $CXXFLAGS -std=c++11 -I. -Ire2/fuzzing/compiler-rt/include/ \
	re2/fuzzing/re2_sydr.cc -o /re2_sydr/re2_sydr -pthread \
	obj/libre2.a

mkdir /re2_cov
make clean
make CXX=clang++ CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fprofile-instr-generate -fcoverage-mapping" -j$(nproc) obj/libre2.a

CXX=clang++
CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fprofile-instr-generate -fcoverage-mapping"
# Second, build the fuzzer (distributed with RE2).
$CXX $CXXFLAGS -std=c++11 -I. -Ire2/fuzzing/compiler-rt/include/ \
	re2/fuzzing/re2_sydr.cc -o /re2_cov/re2_cov -pthread \
	obj/libre2.a
