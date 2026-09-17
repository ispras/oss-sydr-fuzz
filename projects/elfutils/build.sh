#!/usr/bin/env bash

set -eux

function aflpp() {
    CC='afl-clang-fast'

    CC=$CC CXX="${CC}++" $BUILD_SH all /aflpp 1
}

function lf() {
    $BUILD_SH all /libfuzzer 1 
}

function cov() {
    flags="-fprofile-instr-generate -fcoverage-mapping"

    CFLAGS=$flags CXXFLAGS=$flags $BUILD_SH all /cov 0
}

function sydr() {
    $BUILD_SH all /sydr 0 
}

function difuzz() {
    cd $FUZZ_DIR/directed_target/"$1"

    OUT_DIR=$RESULT_DIFUZZ_DIR/"$1"
    mkdir -p $OUT_DIR

    OUT_DIR=$OUT_DIR cargo make all
}

function di_dwfl_core() {
    difuzz dwfl-core
}

function di_libdwfl() {
    difuzz libdwfl
}

function di_libelf() {
    difuzz libelf
}

jobs_set=(aflpp lf cov sydr di_dwfl_core di_libdwfl di_libelf)

export -f "${jobs_set[@]}" difuzz

printf '%s\n' "${jobs_set[@]}" | parallel -j $WORKERS
