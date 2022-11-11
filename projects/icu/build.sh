#!/bin/bash
# Copyright 2017 Google Inc.
# Modifications copyright (C) 2022 ISP RAS
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

# Fix bug in fuzztarget.
cp /collator_compare_fuzzer.cpp /icu/icu4c/source/test/fuzzer/collator_compare_fuzzer.cpp

# Copy enhanced Sydr targets.
cp /*_sydr.cpp /icu/icu4c/source/test/fuzzer/.

# Build libFuzzer targets.
cp -r /icu /icu-fuzz
cd /icu-fuzz

DEFINES="-DU_CHARSET_IS_UTF8=1 -DU_USING_ICU_NAMESPACE=0 -DU_ENABLE_DYLOAD=0 -DU_USE_STRTOD_L=0"
CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero $DEFINES"
CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero $DEFINES"
CC=clang
CXX=clang++

CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS CC=$CC CXX=$CXX \
  /bin/bash ./icu4c/source/runConfigureICU Linux \
   --with-library-bits=64 --with-data-packaging=static --enable-static --disable-shared

export ASAN_OPTIONS="detect_leaks=0"
export UBSAN_OPTIONS="detect_leaks=0"

make -j$(nproc)
$CXX $CXXFLAGS -std=c++11 -c ./icu4c/source/test/fuzzer/locale_util.cpp \
     -I./icu4c/source/test/fuzzer

FUZZER_PATH=/icu/icu4c/source/test/fuzzer
FUZZERS=$FUZZER_PATH/*_fuzzer.cpp

CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
for fuzzer in $FUZZERS; do
  file=${fuzzer:${#FUZZER_PATH}+1}
  $CXX $CXXFLAGS -std=c++11 \
    $fuzzer -o /${file/.cpp/} locale_util.o \
    -I./icu4c/source/common -I./icu4c/source/i18n -L./lib \
    -licui18n -licuuc -licutu -licudata
done

# Build Sydr targets.
cp -r /icu /icu-sydr
cd /icu-sydr

DEFINES="-DU_CHARSET_IS_UTF8=1 -DU_USING_ICU_NAMESPACE=0 -DU_ENABLE_DYLOAD=0 -DU_USE_STRTOD_L=0"
CFLAGS="-g $DEFINES"
CXXFLAGS="-g $DEFINES"

CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS CC=$CC CXX=$CXX \
  /bin/bash ./icu4c/source/runConfigureICU Linux \
   --with-library-bits=64 --with-data-packaging=static --enable-static --disable-shared
make -j$(nproc)
$CXX $CXXFLAGS -std=c++11 -c ./icu4c/source/test/fuzzer/locale_util.cpp \
     -I./icu4c/source/test/fuzzer
$CC $CFLAGS -c /main.c -o main.o

for fuzzer in $FUZZERS; do
  file=${fuzzer:${#FUZZER_PATH}+1}
  $CXX $CXXFLAGS -std=c++11 \
    $fuzzer -o /${file/fuzzer.cpp/sydr} main.o locale_util.o \
    -I./icu4c/source/common -I./icu4c/source/i18n -L./lib \
    -licui18n -licuuc -licutu -licudata -lpthread
done
rm /break_iterator_sydr
rm /collator_compare_sydr
rm /converter_sydr
rm /number_format_sydr
rm /ucasemap_sydr
SYDRTARGETS=$FUZZER_PATH/*_sydr.cpp
for sydr in $SYDRTARGETS; do
  file=${sydr:${#FUZZER_PATH}+1}
  $CXX $CXXFLAGS -std=c++11 \
    $sydr -o /${file/.cpp/} locale_util.o \
    -I./icu4c/source/common -I./icu4c/source/i18n -L./lib \
    -licui18n -licuuc -licutu -licudata -lpthread
done


# Build coverage targets.
cp -r /icu /icu-cov
cd /icu-cov

DEFINES="-DU_CHARSET_IS_UTF8=1 -DU_USING_ICU_NAMESPACE=0 -DU_ENABLE_DYLOAD=0 -DU_USE_STRTOD_L=0"
CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping $DEFINES"
CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping $DEFINES"

CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS CC=$CC CXX=$CXX \
  /bin/bash ./icu4c/source/runConfigureICU Linux \
   --with-library-bits=64 --with-data-packaging=static --enable-static --disable-shared
make -j$(nproc)
$CXX $CXXFLAGS -std=c++11 -c ./icu4c/source/test/fuzzer/locale_util.cpp \
     -I./icu4c/source/test/fuzzer
$CC $CFLAGS -c /main.c -o main.o

for fuzzer in $FUZZERS; do
  file=${fuzzer:${#FUZZER_PATH}+1}
  $CXX $CXXFLAGS -std=c++11 \
    $fuzzer -o /${file/fuzzer.cpp/cov} main.o locale_util.o \
    -I./icu4c/source/common -I./icu4c/source/i18n -L./lib \
    -licui18n -licuuc -licutu -licudata -lpthread
done

# Prepare corpuses and dictinary.
CORPUS=./icu4c/source/test/fuzzer/*_fuzzer_seed_corpus.txt
for corpus in $CORPUS; do
    file=${corpus:${#FUZZER_PATH}+1}
    mkdir /${file/fuzzer_seed_corpus.txt/corpus}
    cp $corpus /${file/fuzzer_seed_corpus.txt/corpus}/.
done
cp /icu/icu4c/source/test/fuzzer/*.dict /
