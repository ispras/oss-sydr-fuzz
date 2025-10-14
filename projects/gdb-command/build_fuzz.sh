#!/bin/bash -eu
# Copyright 2021 Google LLC
# Modifications copyright (C) 2025 ISP RAS
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

RUSTFLAGS="-C panic=abort" cargo fuzz build -O
cargo fuzz list | while read i; do
    cp fuzz/target/x86_64-unknown-linux-gnu/release/$i /
done

cd fuzz-afl
RUSTFLAGS="-C debuginfo=2 -C panic=abort" cargo afl build
cp target/debug/from_gdb_afl /afl_from_gdb
