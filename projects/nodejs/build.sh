#!/bin/bash
# Copyright 2017 Google Inc.
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
# libfuzzer
cd /node_libfuzzer

export CC=clang
export CXX=clang++
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,undefined,bounds,null,float-divide-by-zero"
export CFLAGS=$CXXFLAGS
export LDFLAGS="-latomic $CXXFLAGS"

./configure
make -j$(nproc)
ar -rcT static.a $(find . -name "*.o")

export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,undefined,bounds,null,float-divide-by-zero"
NODE_WANT_INTERNALS=1 $CXX $CXXFLAGS -pthread test/fuzzers/fuzz_env.cc -o /load_env_fuzzer -DNODE_WANT_INTERNALS \
     -I./deps/v8/include -I./src/ -I./test/fuzzers/ -I./deps/uv/include/ static.a -ldl -latomic -fno-rtti
NODE_WANT_INTERNALS=1 $CXX $CXXFLAGS -pthread test/fuzzers/fuzz_url.cc -o /load_url_fuzzer -DNODE_WANT_INTERNALS \
     -I./deps/v8/include -I./src/ -I./test/fuzzers/ -I./deps/uv/include/ static.a -ldl -latomic -fno-rtti

# afl
cd /node_afl

export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CXXFLAGS="-g -std=c++17 -fsanitize=address,integer,bounds,null,float-divide-by-zero"
export CFLAGS="-g -fsanitize=address,integer,bounds,null,float-divide-by-zero"
export LDFLAGS="-latomic $CXXFLAGS"

./configure
make -j$(nproc)
ar -rcT static.a $(find . -name "*.o")

$CXX $CXXFLAGS -pthread v8_compile.cpp -o /v8_compile_afl -I./deps/v8/include -I./deps/v8/include/libplatform ./static.a -ldl

export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,undefined,bounds,null,float-divide-by-zero"
$CXX $CXXFLAGS -pthread test/fuzzers/fuzz_env.cc -o /load_env_afl -DNODE_WANT_INTERNALS \
    -I./deps/v8/include -I./src/ -I./test/fuzzers/ -I./deps/uv/include/ static.a -ldl -latomic -fno-rtti
$CXX $CXXFLAGS -pthread test/fuzzers/fuzz_url.cc -o /load_url_afl -DNODE_WANT_INTERNALS \
    -I./deps/v8/include -I./src/ -I./test/fuzzers/ -I./deps/uv/include/ static.a -ldl -latomic -fno-rtti

# Sydr
cd ..
cd /node_sydr

export CC=clang
export CXX=clang++
export CFLAGS="-g"
export CXXFLAGS="-g -std=c++17"
export LDFLAGS="-latomic"

./configure
make -j$(nproc)
ar -rcT static.a $(find . -name "*.o")
$CXX $CXXFLAGS -pthread v8_compile_sydr.cpp -o /v8_compile_sydr \
    -I./deps/v8/include -I./deps/v8/include/libplatform  ./static.a -ldl
$CXX $CXXFLAGS -pthread /sydr_main.cc test/fuzzers/fuzz_env.cc -o /load_env_sydr -DNODE_WANT_INTERNALS \
    -DUSE_INITIALIZE -I./deps/v8/include -I./src/ -I./test/fuzzers/ -I./deps/uv/include/ static.a -ldl -latomic -fno-rtti
$CXX $CXXFLAGS -pthread /sydr_main.cc test/fuzzers/fuzz_url.cc -o /load_url_sydr -DNODE_WANT_INTERNALS \
    -I./deps/v8/include -I./src/ -I./test/fuzzers/ -I./deps/uv/include/ static.a -ldl -latomic -fno-rtti

# coverage
cd ..
cd /node_cov

export CC=clang
export CXX=clang++
export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -std=c++17 -fprofile-instr-generate -fcoverage-mapping"
export LDFLAGS="-latomic $CXXFLAGS"

./configure
make -j$(nproc)
ar -rcT static.a $(find . -name "*.o")
$CXX $CXXFLAGS -pthread v8_compile_sydr.cpp -o /v8_compile_cov \
   -I./deps/v8/include -I./deps/v8/include/libplatform ./static.a -ldl
$CXX $CXXFLAGS -pthread /sydr_main.cc test/fuzzers/fuzz_env.cc -o /load_env_cov -DNODE_WANT_INTERNALS \
    -DUSE_INITIALIZE -I./deps/v8/include -I./src/ -I./test/fuzzers/ -I./deps/uv/include/ static.a -ldl -latomic -fno-rtti
$CXX $CXXFLAGS -pthread /sydr_main.cc test/fuzzers/fuzz_url.cc -o /load_url_cov -DNODE_WANT_INTERNALS \
    -I./deps/v8/include -I./src/ -I./test/fuzzers/ -I./deps/uv/include/ static.a -ldl -latomic -fno-rtti
