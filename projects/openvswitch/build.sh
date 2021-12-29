#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# build fuzzers.
OUT=/openvswitch_fuzzers
mkdir /openvswitch_fuzzers
export CC=clang
export CXX=clang++
export CFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"

./boot.sh && HAVE_UNWIND=no ./configure --enable-ndebug && make -j$(nproc)

export CFLAGS="-g -fsanitize=undefined,address"
export CXXFLAGS="-g -fsanitize=undefined,address"
make oss-fuzz-targets

SRC=/
cp $SRC/openvswitch/tests/oss-fuzz/config/*.dict $OUT/
wget -O $OUT/json.dict https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/json.dict

for file in $SRC/openvswitch/tests/oss-fuzz/*_target;
do
       cp $file $OUT/
       name=$(basename $file)
       corp_name=$(basename $file _target)
       corp_dir=$SRC/ovs-fuzzing-corpus/${corp_name}_seed_corpus
       if [ -d ${corp_dir} ]; then
           cp -r ${corp_dir} $OUT/corpus_${corp_name}
       fi
done

# build sydr targets.
make clean
OUT=/openvswitch_sydr
mkdir /openvswitch_sydr
export CC=clang
export CXX=clang++
export CFLAGS="-g"
export CXXFLAGS="-g"
export LIB_FUZZING_ENGINE="main.o"
$CC $CFLAGS -c main.c -o $LIB_FUZZING_ENGINE

./boot.sh && HAVE_UNWIND=no ./configure --enable-ndebug && make -j$(nproc)

make oss-fuzz-targets

for file in $SRC/openvswitch/tests/oss-fuzz/*_target;
do
       cp $file $OUT/
done

# build cov targets.
make clean
OUT=/openvswitch_cov
mkdir /openvswitch_cov
export CC=clang
export CXX=clang++
export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export LIB_FUZZING_ENGINE="main.o"
$CC $CFLAGS -c main.c -o $LIB_FUZZING_ENGINE

./boot.sh && HAVE_UNWIND=no ./configure --enable-ndebug && make -j$(nproc)

make oss-fuzz-targets

for file in $SRC/openvswitch/tests/oss-fuzz/*_target;
do
       cp $file $OUT/
done
