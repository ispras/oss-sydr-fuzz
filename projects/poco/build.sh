#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Build targets for libfuzzer

mkdir cmake-build
cd cmake-build
cmake -DBUILD_SHARED_LIBS=OFF \
      -DENABLE_TESTS=OFF \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_CXX_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
      ..
make -j$(nproc)
CXX="clang++"
CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

# Building JSON fuzztarget for Poco
$CXX $CXXFLAGS -DPOCO_ENABLE_CPP11 -DPOCO_ENABLE_CPP14 \
    -DPOCO_HAVE_FD_EPOLL -DPOCO_OS_FAMILY_UNIX \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE \
    -D_REENTRANT -D_THREAD_SAFE -D_XOPEN_SOURCE=500 \
    -I/poco/JSON/include \
    -I/poco/Foundation/include \
    -O2 -g -DNDEBUG -std=gnu++14 \
    -o json_fuzzer.o -c /json_parse_fuzzer.cc

$CXX $CXXFLAGS json_fuzzer.o \
    ./lib/libPocoJSON.a \
    ./lib/libPocoFoundation.a \
    -o /json_parser_fuzzer -lpthread -ldl -lrt

# Building XML fuzztarget for Poco
$CXX $CXXFLAGS -DPOCO_ENABLE_CPP11 -DPOCO_ENABLE_CPP14 \
    -DPOCO_HAVE_FD_EPOLL -DPOCO_OS_FAMILY_UNIX \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE \
    -D_REENTRANT -D_THREAD_SAFE -D_XOPEN_SOURCE=500 \
    -I/poco/XML/include \
    -I/poco/Foundation/include \
    -O2 -g -DNDEBUG -std=gnu++14 \
    -o xml_fuzzer.o -c /xml_parse_fuzzer.cc

$CXX $CXXFLAGS xml_fuzzer.o \
    ./lib/libPocoXML.a \
    ./lib/libPocoFoundation.a \
    -o /xml_parser_fuzzer -lpthread -ldl -lrt

# Build targets for Sydr

cd .. && rm -rf cmake-build && mkdir cmake-build && cd cmake-build
cmake -DBUILD_SHARED_LIBS=OFF \
      -DENABLE_TESTS=OFF \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_CXX_FLAGS=-g \
      ..
make -j$(nproc)
CXX="clang++"
CXXFLAGS="-g"

# Building JSON sydr target for Poco
$CXX $CXXFLAGS -DPOCO_ENABLE_CPP11 -DPOCO_ENABLE_CPP14 \
    -DPOCO_HAVE_FD_EPOLL -DPOCO_OS_FAMILY_UNIX \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE \
    -D_REENTRANT -D_THREAD_SAFE -D_XOPEN_SOURCE=500 \
    -I/poco/JSON/include \
    -I/poco/Foundation/include \
    -O2 -g -DNDEBUG -std=gnu++14 \
    -o json_sydr.o -c /json_parse_sydr.cc

$CXX $CXXFLAGS  json_sydr.o \
    ./lib/libPocoJSON.a \
    ./lib/libPocoFoundation.a \
    -o /json_parser_sydr -lpthread -ldl -lrt

# Building XML sydr target for Poco
$CXX $CXXFLAGS -DPOCO_ENABLE_CPP11 -DPOCO_ENABLE_CPP14 \
    -DPOCO_HAVE_FD_EPOLL -DPOCO_OS_FAMILY_UNIX \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE \
    -D_REENTRANT -D_THREAD_SAFE -D_XOPEN_SOURCE=500 \
    -I/poco/XML/include \
    -I/poco/Foundation/include \
    -O2 -g -DNDEBUG -std=gnu++14 \
    -o xml_sydr.o -c /xml_parse_sydr.cc

$CXX $CXXFLAGS  xml_sydr.o \
    ./lib/libPocoXML.a \
    ./lib/libPocoFoundation.a \
    -o /xml_parser_sydr -lpthread -ldl -lrt

# Build targets for llvm-cov

cd .. && rm -rf cmake-build && mkdir cmake-build && cd cmake-build

cmake -DBUILD_SHARED_LIBS=OFF \
      -DENABLE_TESTS=OFF \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping"  \
      ..

make -j$(nproc)
CXX="clang++"
CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
LDFLAGS="-fprofile-instr-generate"

# Building JSON cov target for Poco
$CXX $CXXFLAGS -DPOCO_ENABLE_CPP11 -DPOCO_ENABLE_CPP14 \
    -DPOCO_HAVE_FD_EPOLL -DPOCO_OS_FAMILY_UNIX \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE \
    -D_REENTRANT -D_THREAD_SAFE -D_XOPEN_SOURCE=500 \
    -I/poco/JSON/include \
    -I/poco/Foundation/include \
    -O2 -g -DNDEBUG -std=gnu++14 \
    -o json_cov.o -c /json_parse_sydr.cc

$CXX $CXXFLAGS  json_cov.o \
    ./lib/libPocoJSONd.a \
    ./lib/libPocoFoundationd.a \
    -o /json_parser_cov -lpthread -ldl -lrt

# Building XML cov target for Poco
$CXX $CXXFLAGS -DPOCO_ENABLE_CPP11 -DPOCO_ENABLE_CPP14 \
    -DPOCO_HAVE_FD_EPOLL -DPOCO_OS_FAMILY_UNIX \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE \
    -D_REENTRANT -D_THREAD_SAFE -D_XOPEN_SOURCE=500 \
    -I/poco/XML/include \
    -I/poco/Foundation/include \
    -O2 -g -DNDEBUG -std=gnu++14 \
    -o xml_cov.o -c /xml_parse_sydr.cc

$CXX $CXXFLAGS  xml_cov.o \
    ./lib/libPocoXMLd.a \
    ./lib/libPocoFoundationd.a \
    -o /xml_parser_cov -lpthread -ldl -lrt
