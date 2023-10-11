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

#!/bin/bash -eu

cd /libcue

mkdir afl && cd afl

CC=afl-clang-lto
TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"

export AFL_LLVM_DICT2FILE=/libcue.dict
cmake -DCMAKE_C_COMPILER=$CC \
	-DCMAKE_C_FLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" \
	..
make -j$(nproc)

$CC $TARGET_CFLAGS -I/libcue /fuzz_cue_parse_string.c libcue.a -o fuzz_cue_parse_string

cd ..

mkdir libfuzzer && cd libfuzzer

CC=clang
cmake -DCMAKE_C_COMPILER=$CC \
	-DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
	..
make -j$(nproc)

$CC $TARGET_CFLAGS -I/libcue /fuzz_cue_parse_string.c libcue.a -o fuzz_cue_parse_string

cd ..

mkdir cover && cd cover

TARGET_CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

cmake -DCMAKE_C_COMPILER=$CC \
	-DCMAKE_C_FLAGS="$TARGET_CFLAGS" \
	..
make -j$(nproc)

$CC $TARGET_CFLAGS -I/libcue /opt/StandaloneFuzzTargetMain.c /fuzz_cue_parse_string.c libcue.a -o fuzz_cue_parse_string

cd ..

mkdir sydr && cd sydr

TARGET_CFLAGS="-g"

cmake -DCMAKE_C_COMPILER=$CC \
	-DCMAKE_C_FLAGS="$TARGET_CFLAGS" \
	..
make -j$(nproc)

$CC $TARGET_CFLAGS -I/libcue /opt/StandaloneFuzzTargetMain.c /fuzz_cue_parse_string.c libcue.a -o fuzz_cue_parse_string

cd .. && mkdir /corpus && cp t/*.cue /corpus
