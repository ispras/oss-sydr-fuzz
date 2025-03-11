#!/bin/bash
# Copyright 2023 ISP RAS
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

set -e

cd /onnx

# Clean previous build
rm -rf build /onnx/.setuptools-cmake-build *.o

echo "Build directory clean"

export ONNX_USE_PROTOBUF_SHARED_LIBS=0
export ONNX_ML=1
export ONNX_NAMESPACE="onnx"

# Build Onnx.
if [[ $TARGET == "fuzz" ]]
then
    CC=clang
    CXX=clang++
    CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "afl" ]]
then
    CC=afl-clang-fast
    CXX=afl-clang-fast++
    CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "hfuzz" ]]
then
    CC=hfuzz-clang
    CXX=hfuzz-clang++
    CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "sydr" ]]
then
    CC=clang
    CXX=clang++
    CFLAGS="-fPIC -g"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "cov" ]]
then
    CC=clang
    CXX=clang++
    CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    CXXFLAGS=$CFLAGS
fi

CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS MAX_JOBS=$(nproc) \
    python3 setup.py build
CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS MAX_JOBS=$(nproc) \
    python3 setup.py install_headers

# Build targets.
TARGET_FLAGS=""
MAIN=""
if [[ $TARGET == "fuzz" || $TARGET == "afl" ]]
then
    TARGET_FLAGS="-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
elif [[ $TARGET == "hfuzz" ]]
then
    TARGET_FLAGS="-fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
else
    $CC $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o ./main.o
    MAIN="./main.o"
fi

if [[ $TARGET == "cov" ]]
then
    TARGET_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
fi

build_target(){
    target=$1
    echo "=========== Build target ${target}_$TARGET ==========="
    # Build target
    $CXX -g -O2 -DONNX_ML=ON -DONNX_NAMESPACE=onnx $TARGET_FLAGS \
	-I/onnx/build/`ls /onnx/build` \
	-I/onnx/.setuptools-cmake-build \
	-I/onnx/.setuptools-cmake-build/third_party \
	/$target.cc -c -o ./$target.o

    # Link target
    $CXX -g -O2 $TARGET_FLAGS -DNDEBUG ./$target.o $MAIN \
        -Wl,--whole-archive,"/onnx/.setuptools-cmake-build/libonnx.a" -Wl,--no-whole-archive \
        -Wl,--whole-archive,"/onnx/.setuptools-cmake-build/libonnx_proto.a" -Wl,--no-whole-archive \
        /protobuf/build_source/libprotobuf.a \
        -lrt -lm -ldl \
        -pthread \
        -o /${target}_$TARGET
}

targets=("parse_model" "parse_graph" "check_model")
for fuzztarget in ${targets[@]}; do
    build_target $fuzztarget &
done

wait
