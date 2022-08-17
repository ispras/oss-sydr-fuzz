# Copyright 2022 ISP RAS
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

# Apply patches to support fuzzing
git apply --ignore-space-change --ignore-whitespace ./sydr-support-fuzzing.diff

# Build sydr binary
CURR_BUILD=sydr-plain
mkdir /$CURR_BUILD
CC=clang CFLAGS="-g" meson -Dfuzz_mode=sydr -Denable_tests=false -Denable_rz_test=false --default-library=static -Dstatic_runtime=false --buildtype=debugoptimized --prefix=/rizin-fuzzing/$CURR_BUILD build-$CURR_BUILD ; ninja -C build-$CURR_BUILD && ninja -C build-$CURR_BUILD install

# Build with AFL++ instrumentation + ASAN enabled
CURR_BUILD=afl-asan
mkdir /$CURR_BUILD
CC=afl-clang-lto CFLAGS="-g -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined" meson -Dfuzz_mode=afl -Denable_tests=false -Denable_rz_test=false --default-library=static -Dstatic_runtime=false --buildtype=debugoptimized --prefix=/rizin-fuzzing/$CURR_BUILD build-$CURR_BUILD ; ninja -C build-$CURR_BUILD && ninja -C build-$CURR_BUILD install

# Build with libfuzzer
CURR_BUILD=libfuzzer-asan
mkdir /$CURR_BUILD
CC=clang CFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined" LDFLAGS="-fsanitize=fuzzer-no-link,address,undefined" meson -Dfuzz_mode=libfuzzer -Denable_tests=false -Denable_rz_test=false --default-library=static -Dstatic_runtime=false --buildtype=debugoptimized --prefix=/rizin-fuzzing/$CURR_BUILD build-$CURR_BUILD ; ninja -C build-$CURR_BUILD && ninja -C build-$CURR_BUILD install

# Coverage build
CURR_BUILD=coverage-plain
mkdir /$CURR_BUILD
# `fuzz_mode=sydr` is expected, in this mode we have default main
CC=clang CFLAGS="-O2 -fno-omit-frame-pointer -g -fprofile-instr-generate -fcoverage-mapping" meson -Dfuzz_mode=sydr -Denable_tests=false -Denable_rz_test=false --default-library=static -Dstatic_runtime=false --buildtype=debugoptimized --prefix=/rizin-fuzzing/$CURR_BUILD build-$CURR_BUILD ; ninja -C build-$CURR_BUILD && ninja -C build-$CURR_BUILD install
