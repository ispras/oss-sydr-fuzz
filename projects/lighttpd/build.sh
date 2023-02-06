#!/bin/bash -eu
# Copyright 2021 Google LLC
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

./autogen.sh 
CC=clang
CXX=clang++
CFLAGS="-fsanitize=fuzzer-nolink,address,undefined"
CXXFLAGS="-fsanitize=fuzzer-nolink,address,undefined"
./configure --without-pcre --enable-static
make
cd src

CFLAGS="-fsanitize=fuzzer,address,undefined"
CXXFLAGS="-fsanitize=fuzzer,address,undefined"

$CC $CFLAGS -c /fuzz_burl.c -I. -I../include
$CXX $CXXFLAGS fuzz_burl.o lighttpd-burl.o lighttpd-buffer.o lighttpd-base64.o lighttpd-ck.o -o /fuzz_burl

CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

$CC $CFLAGS -c /fuzz_burl_cov.c -I. -I../include
$CXX $CXXFLAGS fuzz_burl_cov.o lighttpd-burl.o lighttpd-buffer.o lighttpd-base64.o lighttpd-ck.o -o /fuzz_burl_cov

CXXFLAGS="-g"
CFLAGS="-g"

$CC $CFLAGS -c /fuzz_burl_cov.c -I. -I../include
$CXX $CXXFLAGS fuzz_burl_cov.o lighttpd-burl.o lighttpd-buffer.o lighttpd-base64.o lighttpd-ck.o -o /fuzz_burl_sydr
