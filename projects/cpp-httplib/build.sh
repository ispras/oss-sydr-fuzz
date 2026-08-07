#!/bin/bash -eu

cd test/fuzzing

export CXX=clang++

# libFuzzer build
export CXXFLAGS='-fsanitize=fuzzer,address,undefined'
export OUT='/libfuzzer'

make -j$(nproc) all
mkdir "$OUT"
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'          
make clean

# Sydr build
export CXXFLAGS='-fsanitize=address,undefined standalone_fuzz_target_runner.cpp'
export OUT='/sydr'

make -j$(nproc) all
mkdir "$OUT"
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'          
make clean

# coverge build 
export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping standalone_fuzz_target_runner.cpp"
export OUT='/cov'

make -j$(nproc) all
mkdir "$OUT"
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'          
make clean

# AFL++ build
export CXX=afl-clang-fast++
export CXXFLAGS='-fsanitize=fuzzer,address,undefined'
export OUT='/aflpp'

make -j$(nproc) all
mkdir "$OUT"
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'          

# copy fuzzing corpus and dict
export OUT="/dict"
mkdir "$OUT"
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'    
make clean

ln -sr corpus /corpus

