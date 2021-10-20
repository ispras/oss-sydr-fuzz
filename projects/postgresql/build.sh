#!/bin/bash -eu
# Copyright 2020 Google Inc.
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
cp -r fuzzer src/backend/
git apply --ignore-space-change --ignore-whitespace ./add_fuzzers.diff

useradd fuzzuser
chown -R fuzzuser .
cd bld

CC="clang" CXX="clang++" CFLAGS="" CXXFLAGS="" su fuzzuser -c ../configure
cd src/backend/fuzzer
su fuzzuser -c "make createdb"
chown -R root .
mv temp/data .
cp -r data /out
cd ../../..
cp -r tmp_install /out
make clean

CC="clang" CXX="clang++" \
CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero" \
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero" \
../configure
make -j$(nproc)
cd src/backend/fuzzer
make fuzzer
cp *_fuzzer /out
cd ../../..
make clean

CC="clang" CXX="clang++" \
CFLAGS="-g" \
CXXFLAGS="-g" \
../configure
make -j$(nproc)
cd src/backend/fuzzer
make sydr
cp *_sydr /out
