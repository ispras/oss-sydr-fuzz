#!/bin/bash
# Copyright 2022 Google LLC
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
# Ignore memory leaks from python scripts invoked in the build
export ASAN_OPTIONS="detect_leaks=0"
export MSAN_OPTIONS="halt_on_error=0:exitcode=0:report_umrs=0"
CC="clang"
CXX="clang++"
# Remove -pthread from CFLAGS, this trips up ./configure
# which thinks pthreads are available without any CLI flags
CFLAGS=${CFLAGS//"-pthread"/}
CFLAGS="${CFLAGS} -UNDEBUG -O1 -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
# Ensure assert statements are enabled. It may help identify problems
# earlier if those fire.
if [[ $OUT == "/fuzz" ]]
then
    FUZZFLAGS="integer,undefined,bounds,null,float-divide-by-zero"
    CFLAGS="${CFLAGS} -fsanitize=fuzzer-no-link,${FUZZFLAGS}"
elif [[ $OUT == "/cov" ]]
then
    CFLAGS="${CFLAGS} -fprofile-instr-generate -fcoverage-mapping"
fi

CC=$CC CXX=$CXX CXXFLAGS=$CFLAGS CFLAGS=$CFLAGS LDFLAGS=$CFLAGS ./configure  -prefix $OUT

# We use altinstall to avoid having the Makefile create symlinks
make -j$(nproc) altinstall
echo "BUILDED"
if [[ $OUT == "/fuzz" ]]
then
    CFLAGS="-fsanitize=fuzzer,$FUZZFLAGS"
fi

FUZZ_DIR=Modules/_xxtestfuzz
for fuzz_test in $(cat $FUZZ_DIR/fuzz_tests.txt)
do
  # Build (but don't link) the fuzzing stub with a C compiler
  $CC $CFLAGS  $("$OUT/bin/"python*-config --cflags) $FUZZ_DIR/fuzzer.c \
    -D _Py_FUZZ_ONE -D _Py_FUZZ_$fuzz_test -c -Wno-unused-function \
    -o /cpython3/$fuzz_test.o libpython3.*.a
  if [[ $OUT != "/fuzz" ]]
  then
      $CC $CFLAGS -c /cpython3/main.c -o main.o
      MAIN_OBJ="/cpython3/main.o"
  fi 
  # Link with C++ compiler to appease libfuzzer
  $CXX $CFLAGS -rdynamic $MAIN_OBJ /cpython3/$fuzz_test.o -o "${OUT}"/$fuzz_test \
    $("$OUT/bin/"python*-config --ldflags --embed)
done
make clean
