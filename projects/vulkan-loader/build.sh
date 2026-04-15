#!/bin/bash -eu
#
# Copyright 2023 Google LLC
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

export CC=clang
export CXX=clang++
export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"

rm -rf /vulkan-loader/build
mkdir -p /vulkan-loader/build
cd /vulkan-loader
git apply --ignore-space-change --ignore-whitespace /fuzz-patch.diff

mkdir -p build
cd build

sed -i 's/fput/\/\/fput/g' /vulkan-loader/loader/log.c

cmake -DUPDATE_DEPS=ON -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

ar rcs /libvulkan.a /vulkan-loader/build/loader/CMakeFiles/vulkan.dir/*.o

$CC $CFLAGS -c /opt/StandaloneFuzzTargetMain.c -o /main.o

$CC $CFLAGS -I/vulkan-loader/loader \
    -I/vulkan-loader/loader/generated \
    -I/vulkan-headers/include \
    -I/ \
    -DENABLE_FILE_CALLBACK \
    -c /instance_create_advanced_fuzzer.c -o /instance_create_advanced_fuzzer_cov.o

$CXX $CXXFLAGS /main.o /instance_create_advanced_fuzzer_cov.o \
    -o /instance_create_advanced_fuzzer_cov -lpthread /libvulkan.a

cp /vulkan-keywords.dict /instance_create_advanced_fuzzer.dict

$CC $CXXFLAGS -I/vulkan-loader/loader \
    -I/vulkan-loader/loader/generated \
    -I/vulkan-headers/include \
    -DSPLIT_INPUT \
    -c /instance_enumerate_fuzzer.c -o /instance_enumerate_fuzzer_split_input_cov.o

$CXX $CXXFLAGS /main.o /instance_enumerate_fuzzer_split_input_cov.o \
    -o /instance_enumerate_fuzzer_split_input_cov -lpthread /libvulkan.a

cp /vulkan-keywords.dict /instance_enumerate_fuzzer_split_input.dict

for fuzzer in instance_create_fuzzer json_load_fuzzer settings_fuzzer instance_enumerate_fuzzer; do
    #fuzz_basename=$(basename -s .c $fuzzers)
    $CC $CXXFLAGS -I/vulkan-loader/loader \
        -I/vulkan-loader/loader/generated \
        -I/vulkan-headers/include \
        -c /$fuzzer.c -o /${fuzzer}_cov.o

    $CXX $CXXFLAGS /main.o /${fuzzer}_cov.o \
        -o /${fuzzer}_cov -lpthread /libvulkan.a

    cp /vulkan-keywords.dict /$fuzzer.dict
done
