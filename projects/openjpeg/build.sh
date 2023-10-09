#!/bin/bash -eu
# Copyright 2017 Google Inc.
# Modifications copyright (C) 2023 ISP RAS
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

export SRC="/openjpeg"
export MAIN_LINK=""

if [[ $CONFIG = "libfuzzer" ]]
then
    export CC="clang"
    export CXX="clang++"
    export CFLAGS='-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero'
    export CXXFLAGS='-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero'
    export LINK_FLAGS='-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero'
    export SUFFIX="fuzz"
fi

if [[ $CONFIG = "afl" ]]
then
    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
    export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
    export CXXFLAGS="-g -fsanitize=address,integer,bounds,undefined,null,float-divide-by-zero"
    export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
    export SUFFIX="afl"
fi

if [[ $CONFIG = "sydr" ]]
then
    export CC="clang"
    export CXX="clang++"
    export CFLAGS="-g"
    export CXXFLAGS="-g"
    export LINK_FLAGS="$CFLAGS"
    export SUFFIX="sydr"
    export MAIN_LINK="/main.o"
fi

if [[ $CONFIG = "coverage" ]]
then
    export CC="clang"
    export CXX="clang++"
    export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    export LINK_FLAGS="$CFLAGS"
    export SUFFIX="cov"
fi

# Build openjpeg.
cd /openjpeg
rm -rf build
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make clean -s
make -j$(nproc) -s
cd ../tests/fuzzers

# Build targets.
if [[ $CONFIG = "sydr" || $CONFIG = "coverage" ]]
then
    $CC $CFLAGS -c -o /main.o /opt/StandaloneFuzzTargetMain.c
    export MAIN_LINK="/main.o"
fi

FuzzerFiles=*.cpp
for Filename in $FuzzerFiles; do
    TargetName=$(basename $Filename .cpp)_$SUFFIX
    $CXX $LINK_FLAGS -std=c++11 -I$SRC/src/lib/openjp2 -I$SRC/build/src/lib/openjp2 \
        $Filename $* -o /$TargetName $SRC/build/bin/libopenjp2.a $MAIN_LINK -lm -lpthread
done

# Get corpus.
if [[ $CONFIG = "coverage" ]]
then
    mkdir /corpus
    cp -R -f -n /data/input/conformance/*.* /data/input/nonregression/htj2k/*.* \
        /data/input/nonregression/*.* /data/input/nonregression/pngsuite/*.* /corpus
    rm -rf /data
    cd /corpus && find -type f -size +1M -delete
fi
