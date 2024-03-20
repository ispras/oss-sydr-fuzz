# Copyright 2024 ISP RAS
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

FUZZER_LIST="fuzzer-parse_json fuzzer-parse_bson fuzzer-parse_cbor
    fuzzer-parse_msgpack fuzzer-parse_ubjson fuzzer-parse_bjdata"

cp ../single_include/nlohmann/json.hpp json.cpp

# libFuzzer
CXX=clang++
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
OUT="/lf_targets"

$CXX $CXXFLAGS json.cpp -c -o libjson.o

CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

mkdir $OUT
for fuzzer in $FUZZER_LIST
do
    $CXX $CXXFLAGS -I ../include -std=c++11 src/$fuzzer.cpp libjson.o -o $OUT/$fuzzer\_fuzzer
done

# AFL++
CXX=afl-clang-fast++
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
OUT="/afl_targets"

$CXX $CXXFLAGS json.cpp -c -o libjson.o

CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

mkdir $OUT
for fuzzer in $FUZZER_LIST
do
    $CXX $CXXFLAGS -I ../include -std=c++11 src/$fuzzer.cpp libjson.o -o $OUT/$fuzzer\_afl
done

# Sydr
CC=clang
CXX=clang++
CXXFLAGS="-g"
OUT="/sydr_targets"

$CXX $CXXFLAGS json.cpp -c -o libjson.o

$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o
mkdir $OUT
for fuzzer in $FUZZER_LIST
do
    $CXX $CXXFLAGS -I ../include -std=c++11 main.o src/$fuzzer.cpp libjson.o -o $OUT/$fuzzer\_sydr
done

# Coverage
CC=clang
CXX=clang++
CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
OUT="/cov_targets"

$CXX $CXXFLAGS json.cpp -c -o libjson.o

$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o
mkdir $OUT
for fuzzer in $FUZZER_LIST
do
    $CXX $CXXFLAGS -I ../include -std=c++11 main.o src/$fuzzer.cpp libjson.o -o $OUT/$fuzzer\_cov
done

rm main.o libjson.o
