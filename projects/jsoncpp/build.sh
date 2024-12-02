#!/bin/bash -eu
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

# libFuzzer
mkdir build
cd build

CC=clang
CXX=clang++
CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
OUT="lf"

cmake .. -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles"
make "-j$(nproc)"

mkdir /$OUT

# Compile fuzzer.
$CXX $CXXFLAGS -I../include \
    ../src/test_lib_json/fuzz.cpp -o /$OUT/jsoncpp_fuzz_$OUT \
    /jsoncpp/build/lib/libjsoncpp.a

if [[ $CFLAGS != *sanitize=memory* ]]; then
# Compile json proto.
rm -rf genfiles && mkdir genfiles && ../LPM/external.protobuf/bin/protoc /proto/json.proto \
    --cpp_out=genfiles --proto_path=/proto

# Compile LPM fuzzer.
$CXX $CXXFLAGS -DNDEBUG -I genfiles -I .. -I ../libprotobuf-mutator/ -I ../LPM/external.protobuf/include -I ../include \
    -pthread \
    /proto/jsoncpp_fuzz_proto.cc genfiles/json.pb.cc /proto/json_proto_converter.cc \
    ../LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    ../LPM/src/libprotobuf-mutator.a \
    -Wl,--start-group ../LPM/external.protobuf/lib/lib*.a -Wl,--end-group \
    -o  /$OUT/jsoncpp_proto_fuzz_$OUT \
    /jsoncpp/build/lib/libjsoncpp.a
fi

# json-protobuf packer
cd ..
rm -rf build
mkdir build
cd build

CC=clang
CXX=clang++
CFLAGS="-g"
CXXFLAGS="-g"
OUT="pack"

cmake .. -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles"
make "-j$(nproc)"

mkdir /$OUT

if [[ $CFLAGS != *sanitize=memory* ]]; then
# Compile json proto.
rm -rf genfiles && mkdir genfiles && ../LPM/external.protobuf/bin/protoc /proto/json.proto \
    --cpp_out=genfiles --proto_path=/proto

# Compile both-sided json-protobuf packer.
clang++ -g -I genfiles -I ../LPM/external.protobuf/include -I ../libprotobuf-mutator/ -I .. -I /proto \
  genfiles/json.pb.cc /proto/json_proto_converter.cc /proto/main_packer.cc /proto/json_packer.cc \
  ../LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a ../LPM/src/libprotobuf-mutator.a \
  -Wl,--start-group ../LPM/external.protobuf/lib/lib*.a -Wl,--end-group \
  -o /$OUT/json_packer -lpthread
fi

# AFL
cd ..
rm -rf build
mkdir build
cd build

CC=afl-clang-fast
CXX=afl-clang-fast++
CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
OUT="afl"

cmake .. -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles"
make "-j$(nproc)"

mkdir /$OUT
$CXX $CXXFLAGS -I../include \
    ../src/test_lib_json/fuzz.cpp -o /$OUT/jsoncpp_fuzz_$OUT \
    /jsoncpp/build/lib/libjsoncpp.a

if [[ $CFLAGS != *sanitize=memory* ]]; then
# Compile json proto.
rm -rf genfiles && mkdir genfiles && ../LPM/external.protobuf/bin/protoc /proto/json.proto \
    --cpp_out=genfiles --proto_path=/proto

# Compile LPM fuzzer.
$CXX $CXXFLAGS -DNDEBUG -I genfiles -I .. -I ../libprotobuf-mutator/ -I ../LPM/external.protobuf/include -I ../include \
    -pthread \
    /proto/jsoncpp_fuzz_proto.cc genfiles/json.pb.cc /proto/json_proto_converter.cc \
    ../LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    ../LPM/src/libprotobuf-mutator.a \
    -Wl,--start-group ../LPM/external.protobuf/lib/lib*.a -Wl,--end-group \
    -o  /$OUT/jsoncpp_proto_fuzz_$OUT \
    /jsoncpp/build/lib/libjsoncpp.a
fi

# Sydr
cd ..
rm -rf build
mkdir build
cd build

CC=clang
CXX=clang++
CFLAGS="-g"
CXXFLAGS="-g"
OUT="sydr"

mkdir /$OUT
$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o

cmake .. -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles"
make "-j$(nproc)"

$CXX $CXXFLAGS -I../include \
    ../src/test_lib_json/fuzz.cpp main.o -o /$OUT/jsoncpp_fuzz_$OUT \
    /jsoncpp/build/lib/libjsoncpp.a

if [[ $CFLAGS != *sanitize=memory* ]]; then
# Compile json proto.
rm -rf genfiles && mkdir genfiles && ../LPM/external.protobuf/bin/protoc /proto/json.proto \
    --cpp_out=genfiles --proto_path=/proto

# Compile LPM fuzzer.
$CXX $CXXFLAGS -DNDEBUG -I genfiles -I .. -I ../libprotobuf-mutator/ -I ../LPM/external.protobuf/include -I ../include \
    -pthread \
    /proto/jsoncpp_fuzz_proto.cc genfiles/json.pb.cc /proto/json_proto_converter.cc \
    ../LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    ../LPM/src/libprotobuf-mutator.a \
    -Wl,--start-group ../LPM/external.protobuf/lib/lib*.a -Wl,--end-group \
    -o  /$OUT/jsoncpp_proto_fuzz_$OUT \
    /jsoncpp/build/lib/libjsoncpp.a main.o
fi

# coverage
cd ..
rm -rf build
mkdir build
cd build

CC=clang
CXX=clang++
CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
OUT="cov"

mkdir /$OUT
$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o

cmake .. -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles"
make "-j$(nproc)"

$CXX $CXXFLAGS -I../include \
    ../src/test_lib_json/fuzz.cpp main.o -o /$OUT/jsoncpp_fuzz_$OUT \
    /jsoncpp/build/lib/libjsoncpp.a

if [[ $CFLAGS != *sanitize=memory* ]]; then
# Compile json proto.
rm -rf genfiles && mkdir genfiles && ../LPM/external.protobuf/bin/protoc /proto/json.proto \
    --cpp_out=genfiles --proto_path=/proto

# Compile LPM fuzzer.
$CXX $CXXFLAGS -DNDEBUG -I genfiles -I .. -I ../libprotobuf-mutator/ -I ../LPM/external.protobuf/include -I ../include \
    -pthread \
    /proto/jsoncpp_fuzz_proto.cc genfiles/json.pb.cc /proto/json_proto_converter.cc \
    ../LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    ../LPM/src/libprotobuf-mutator.a \
    -Wl,--start-group ../LPM/external.protobuf/lib/lib*.a -Wl,--end-group \
    -o  /$OUT/jsoncpp_proto_fuzz_$OUT \
    /jsoncpp/build/lib/libjsoncpp.a main.o
fi
