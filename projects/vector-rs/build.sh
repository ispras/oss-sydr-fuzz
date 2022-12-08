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
mkdir /fuzz /sydr
# afl
cd /vector/lib/vrl/stdlib/fuzzing
RUSTFLAGS="-Zsanitizer=address" cargo afl build --bin fuzz_aws --target x86_64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=address" cargo afl build --bin fuzz_csv --target x86_64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=address" cargo afl build --bin fuzz_json --target x86_64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=address" cargo afl build --bin fuzz_klog --target x86_64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=address" cargo afl build --bin fuzz_xml --target x86_64-unknown-linux-gnu
find /vector/lib/vrl/stdlib/fuzzing/target/x86_64-unknown-linux-gnu/debug -maxdepth 1 -perm /a+x -name "fuzz_*" -exec cp {} /fuzz \;

#sydr
cargo build --bin cov_aws --target x86_64-unknown-linux-gnu
cargo build --bin cov_csv --target x86_64-unknown-linux-gnu
cargo build --bin cov_json --target x86_64-unknown-linux-gnu
cargo build --bin cov_klog --target x86_64-unknown-linux-gnu
cargo build --bin cov_xml --target x86_64-unknown-linux-gnu
find /vector/lib/vrl/stdlib/fuzzing/target/x86_64-unknown-linux-gnu/debug -maxdepth 1 -perm /a+x -name "cov_*" -exec cp {} /sydr \;
