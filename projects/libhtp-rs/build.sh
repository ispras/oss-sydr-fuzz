#!/bin/bash -eu

cd /libhtp-rs/fuzz/

export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
export RUSTFLAGS="-C debug-assertions -C overflow_checks -C debuginfo=2"

cargo +nightly fuzz build -O
cp target/x86_64-unknown-linux-gnu/release/fuzz_htp_rs /cargo_fuzz_htp_rs

unset RUSTFLAGS

cd /libhtp-rs/afl/

export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"

cargo afl build
cp target/x86_64-unknown-linux-gnu/debug/fuzz_htp_rs /afl_fuzz_htp_rs

cd /libhtp-rs/sydr_and_cover/

export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
cargo build
cp target/x86_64-unknown-linux-gnu/debug/sydr_htp_rs /sydr_fuzz_htp_rs

unset CARGO_BUILD_TARGET

cd /libhtp-rs/sydr_and_cover/

cargo clean

export RUSTFLAGS="-C instrument-coverage"

cargo build
cp target/debug/sydr_htp_rs /cover_fuzz_htp_rs
