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
$CXX $CXXFLAGS -D_GLIBCXX_DEBUG -I /rapidjson/include fuzzer.cpp -o /rapidjson-fuzzer/rapidjson-fuzzer

CFLAGS="-g"
CXXFLAGS="-g"
$CXX $CXXFLAGS -D_GLIBCXX_DEBUG -I /rapidjson/include rapidjson-sydr.cpp -o /rapidjson-sydr/rapidjson-sydr

# Disabled because compiliation fails for reasons unknown.
# Using the exact same compile commands locally does not fail.
# Try enabling again in the future.
#cd $SRC/fuzzing-headers/tests
#$CXX $CXXFLAGS -std=c++2a -D_GLIBCXX_DEBUG -I $SRC/rapidjson/include -I ../include rapidjson.cpp $LIB_FUZZING_ENGINE -o $OUT/fuzzer-extended
