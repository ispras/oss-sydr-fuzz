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


JWT_DIR=/nginx-auth-jwt
JANSSON_DIR=/jansson
JANSSON_OUT=""
JWT_OUT=""
MAIN=/opt/StandaloneFuzzTargetMain.c

cd /$JWT_DIR && git apply /jwt.patch

build_libs() {
    origin=$(pwd)
    JANSSON_OUT=$JANSSON_DIR/build$SUFFIX
    JWT_OUT=$JWT_DIR/build$SUFFIX
    rm -rf $JANSSON_OUT && mkdir $JANSSON_OUT
    rm -rf $JWT_OUT && mkdir $JWT_OUT

    cd $JANSSON_OUT

    cmake .. -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
            -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS"
    CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

    cd $JWT_DIR

    for file in $(find $JWT_DIR/src -name "*.c") 
    do
        filename=$(basename $file)
        filename="${filename%.*}"
        if [[ $filename == "ngx_http_auth_jwt_module" || $filename == "jwt_requirement_operators" ]]; then
            continue
        fi
        $CC $CFLAGS $file $JANSSON_OUT/lib/libjansson.a -I$JANSSON_OUT/include/ -c -g \
            -DFUZZER=1 -o $JWT_OUT/$filename.o
    done
    
    ar rcs $JWT_OUT/libjwt.a $JWT_OUT/*
    cd $origin
}

# Build libFuzzer fuzz targets.

CC="clang"
CXX="clang++"
CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
SUFFIX="_lf"

build_libs

CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

for fuzz_target in /fuzz_targets/*
do
    filename=$(basename $fuzz_target)
    filename="${filename%.*}"
    $CC $CXXFLAGS $fuzz_target $JWT_OUT/libjwt.a $JANSSON_OUT/lib/libjansson.a \
        -lssl -lcrypto  -I $JWT_DIR/src -I$JANSSON_OUT/include -o /$filename$SUFFIX 
done

# Build AFL++ fuzz targets.

CC="afl-clang-fast"
CXX="afl-clang-fast++"
CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
SUFFIX="_afl"

build_libs

CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

for fuzz_target in /fuzz_targets/*
do
    filename=$(basename $fuzz_target)
    filename="${filename%.*}"
    $CC $CXXFLAGS $fuzz_target $JWT_OUT/libjwt.a $JANSSON_OUT/lib/libjansson.a \
        -lssl -lcrypto  -I $JWT_DIR/src -I$JANSSON_OUT/include -o /$filename$SUFFIX 
done

# Build Sydr fuzz targets.

CC="clang"
CXX="clang++"
CFLAGS="-g"
CXXFLAGS="-g"
SUFFIX="_sydr"

build_libs

for fuzz_target in /fuzz_targets/*
do
    filename=$(basename $fuzz_target)
    filename="${filename%.*}"
    $CC $CXXFLAGS $MAIN $fuzz_target $JWT_OUT/libjwt.a $JANSSON_OUT/lib/libjansson.a \
        -lssl -lcrypto  -I $JWT_DIR/src -I$JANSSON_OUT/include -o /$filename$SUFFIX 
done

# Build Coverage fuzz targets.

CC="clang"
CXX="clang++"
CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
SUFFIX="_cov"

build_libs

for fuzz_target in /fuzz_targets/*
do
    filename=$(basename $fuzz_target)
    filename="${filename%.*}"
    $CC $CXXFLAGS $MAIN $fuzz_target $JWT_OUT/libjwt.a $JANSSON_OUT/lib/libjansson.a \
        -lssl -lcrypto  -I $JWT_DIR/src -I$JANSSON_OUT/include -o /$filename$SUFFIX 
done
