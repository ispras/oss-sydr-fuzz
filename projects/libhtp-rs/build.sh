#!/bin/bash -eu
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

cd /libhtp-rs/fuzz/

export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
export RUSTFLAGS="-C debug-assertions -C overflow_checks -C debuginfo=2 -C panic=abort"

cargo fuzz build -O
cp target/x86_64-unknown-linux-gnu/release/fuzz_htp_rs /cargo_fuzz_htp_rs

unset RUSTFLAGS
export RUSTFLAGS="-C debuginfo=2 -C panic=abort"

cd /libhtp-rs/afl/

export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"

cargo afl build --release
cp target/x86_64-unknown-linux-gnu/release/fuzz_htp_rs /afl_fuzz_htp_rs

cd /libhtp-rs/sydr_and_cover/

export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
export RUSTFLAGS="-C debug-assertions -C overflow_checks -C debuginfo=2 -C panic=abort"
cargo build --release
cp target/x86_64-unknown-linux-gnu/release/sydr_htp_rs /sydr_fuzz_htp_rs

unset CARGO_BUILD_TARGET

cd /libhtp-rs/sydr_and_cover/

cargo clean

unset RUSTFLAGS
export RUSTFLAGS="-C instrument-coverage -C debuginfo=2 -C panic=abort"

cargo build --release
cp target/release/sydr_htp_rs /cover_fuzz_htp_rs
