#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

CXX="clang++"
CXXFLAGS="-g -DASAN -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero -fsanitize-recover=address "
$CXX $CXXFLAGS -D_GLIBCXX_DEBUG -I /rapidjson/include fuzzer.cpp -o /parser_fuzz

CXX="afl-clang-lto++"
CXXFLAGS="-g -DASAN -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero -fsanitize-recover=address"
$CXX $CXXFLAGS -D_GLIBCXX_DEBUG -I /rapidjson/include fuzzer.cpp -o /parser_afl

clang -c /opt/StandaloneFuzzTargetMain.c -o /StandaloneFuzzTargetMain.o

CXX="clang++"
CFLAGS="-g"
CXXFLAGS="-g"
$CXX $CXXFLAGS -D_GLIBCXX_DEBUG -I /rapidjson/include fuzzer.cpp /StandaloneFuzzTargetMain.o -o /parser_sydr

CXX="clang++"
CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
$CXX $CXXFLAGS -D_GLIBCXX_DEBUG -I /rapidjson/include fuzzer.cpp /StandaloneFuzzTargetMain.o -o /parser_cov
