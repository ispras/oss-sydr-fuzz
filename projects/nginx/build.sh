#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# Save fuzz target
mkdir /nginx/src/fuzz
cd /nginx/src/fuzz
wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/fuzz/http_request_fuzzer.cc
wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/fuzz/http_request_proto.proto
wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/fuzz/wrappers.c

# Save additional files for libFuzzer and AFL++ builds
cd /
wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/add_fuzzers.diff
wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/make_fuzzers
wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/nginx/fuzz/http_request_fuzzer.dict

# Make a copy for Sydr and cov builds
cp -r /nginx /nginx_sydr
cd /nginx

# Apply diff for libFuzzer and AFL++ builds
hg import /add_fuzzers.diff --no-commit
cp /make_fuzzers auto/make_fuzzers

cd src/fuzz
rm -rf genfiles && mkdir genfiles && /LPM/external.protobuf/bin/protoc http_request_proto.proto --cpp_out=genfiles
cd ../..

# Build targets for libfuzzer
export CC=clang
export CXX=clang++
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"

auto/configure \
    --with-http_v2_module
make -f objs/Makefile modules

export CC=clang
export CXX=clang++
export CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
make -f objs/Makefile fuzzers

for fuzzer in objs/*_fuzzer;
do
    fuzzer_name=$(basename $fuzzer)
    fuzzer_name=${fuzzer_name::-7}
    cp $fuzzer /${fuzzer_name}_lf
done

# Build targets for AFL++
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"

auto/configure \
    --with-http_v2_module
make -f objs/Makefile modules

export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

make -f objs/Makefile fuzzers

for fuzzer in objs/*_fuzzer;
do
    fuzzer_name=$(basename $fuzzer)
    fuzzer_name=${fuzzer_name::-7}
    cp $fuzzer /${fuzzer_name}_afl
done

# Apply diff for Sydr and cov builds
cd ../nginx_sydr
hg import /add_sydr.diff --no-commit
cp /make_sydr auto/make_sydr

cd src/fuzz
rm -rf genfiles && mkdir genfiles && /LPM/external.protobuf/bin/protoc http_request_proto.proto --cpp_out=genfiles
cd ../..

# Build targets for Sydr
export CC=clang
export CXX=clang++
export CFLAGS="-g -fPIE"
export CXXFLAGS="-g -fPIE"

auto/configure \
    --with-http_v2_module

make -f objs/Makefile fuzzers

for fuzzer in objs/*_fuzzer;
do
    fuzzer_name=$(basename $fuzzer)
    fuzzer_name=${fuzzer_name::-7}
    cp $fuzzer /${fuzzer_name}_sydr
done

# Build targets for cov
export CC=clang
export CXX=clang++
export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -fPIE"
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping -fPIE"

auto/configure \
    --with-http_v2_module

make -f objs/Makefile fuzzers

for fuzzer in objs/*_fuzzer;
do
    fuzzer_name=$(basename $fuzzer)
    fuzzer_name=${fuzzer_name::-7}
    cp $fuzzer /${fuzzer_name}_cov
done

# Prepare seed corpora
cd /
git clone https://github.com/dvyukov/go-fuzz-corpus.git /go-fuzz-corpus
cp -r /go-fuzz-corpus/http2/corpus /corpus
cp /go-fuzz-corpus/httpreq/corpus/* /corpus
rm /corpus/da39a3ee5e6b4b0d3255bfef95601890afd80709-2
rm /corpus/da39a3ee5e6b4b0d3255bfef95601890afd80709-1
