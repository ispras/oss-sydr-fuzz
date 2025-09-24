#!/bin/bash
# Copyright 2025 ISP RAS
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

cd /ncnn

# Clean previous build
rm -rf build

install_dir=/install_ncnn

echo "Build directory clean"

# Set build flags.
if [[ $TARGET == "fuzz" ]]
then
    # Set libfuzzer instrumentation flags
    CC=clang
    CXX=clang++
    CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "afl" ]]
then
    # Set AFL++ instrumentation flags
    CC=afl-clang-fast
    CXX=afl-clang-fast++
    CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "hfuzz" ]]
then
    # Set honggfuzz instrumentation flags
    CC=hfuzz-clang
    CXX=hfuzz-clang++
    CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "sydr" ]]
then
    # Set flags to build `clean` binary with debug info only
    CC=clang
    CXX=clang++
    CFLAGS="-fPIC -g"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "cov" ]]
then
    # Set coverage instrumentation flags
    CC=clang
    CXX=clang++
    CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    CXXFLAGS=$CFLAGS
fi

# Build ncnn
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDeb -DNCNN_INT8=ON -DCMAKE_INSTALL_PREFIX=$install_dir \
      -DBUILD_SHARED_LIBS=OFF -DUSE_NCNN_SIMPLEOCV=ON -DNCNN_BUILD_EXAMPLES=OFF ..
make -j$(nproc)
make install

# Build fuzz targets.
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

EXTRA_FLAGS=""
EXTRA_ADD_OBJ=""

build_target(){
    target=$1
    echo "=========== Build target ${target}_$TARGET ==========="
    EXTRA_FLAGS=""
    EXTRA_ADD_OBJ=""

    # Build target
    if [[ $target == "ncnn_imread" ]]
    then
        EXTRA_FLAGS="-DUSE_NCNN_SIMPLEOCV -DNCNN_SIMPLEOCV"
        $CXX -g -O2 $TARGET_FLAGS $EXTRA_FLAGS \
            -I/install_ncnn/include -I/ncnn/tools/ \
            -I/ncnn/src/ -I/ncnn/build/src/ \
            -I/ncnn/toos/quantize/ \
            -I/ncnn/ -stdlib=libstdc++ \
            /ncnn/tools/quantize/imreadwrite.cpp -c -o ./imread_ocv.o
        EXTRA_ADD_OBJ="./imread_ocv.o"
    fi

    $CXX -g -O2 $TARGET_FLAGS $EXTRA_FLAGS \
	-I/install_ncnn/include -I/ncnn/tools/ \
        -I/ncnn/src/ -I/ncnn/build/src/ \
        -I/ncnn/ -stdlib=libstdc++ \
	/$target.cc -c -o ./$target.o

    # Link target
    $CXX -g -O2 $TARGET_FLAGS -DNDEBUG $EXTRA_FLAGS $EXTRA_ADD_OBJ ./$target.o $MAIN \
        -Wl,--whole-archive,"/install_ncnn/lib/libncnn.a" -Wl,--no-whole-archive \
        -L/install_ncnn/lib \
        -L/usr/lib/riscv64-linux-gnu/ \
        -L/lib/riscv64-linux-gnu \
        -L/usr/lib/llvm-18/lib \
        -fopenmp -lrt -lm -ldl \
        -pthread -fopenmp -stdlib=libstdc++ \
        -o /${target}_$TARGET
}

targets=("ncnn_imread" "darknet_cfg" "mxnet_json_read")
for fuzztarget in ${targets[@]}; do
    build_target $fuzztarget &
done

wait
