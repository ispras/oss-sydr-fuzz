#!/bin/bash -eu

cd test/fuzzing

export CXX=clang++

# libFuzzer build
export CXXFLAGS='-fsanitize=fuzzer'
export OUT='/libfuzzer'

make -j$(nproc) server_fuzzer
mkdir "$OUT"
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'          
make clean

# Sydr build
export CXXFLAGS='standalone_fuzz_target_runner.cpp'
export OUT='/sydr'

make -j$(nproc) server_fuzzer
mkdir "$OUT"
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'          
make clean

# coverge build 
export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping standalone_fuzz_target_runner.cpp"
export OUT='/cov'

make -j$(nproc) server_fuzzer
mkdir "$OUT"
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'          
make clean

# AFL++ build
export CXX=afl-clang-fast++
export CXXFLAGS='-fsanitize=fuzzer'
export OUT='/aflpp'

make -j$(nproc) server_fuzzer
mkdir "$OUT"
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'          

# copy fuzzing corpus and dict
export OUT="/dict"
mkdir "$OUT"
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'    

ln -sr corpus /corpus

make clean
