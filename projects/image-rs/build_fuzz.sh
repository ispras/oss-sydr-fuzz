#!/bin/bash -eu
# Copyright 2021 Google LLC
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
cd ./fuzz-afl

RUSTFLAGS="-C debuginfo=2 -C panic=abort" cargo afl build --release
cp ./target/release/fuzz_pnm /
cp ./target/release/fuzz_webp /
cp ./target/release/fuzz_bmp /
cp ./target/release/fuzz_exr /
cp ./target/release/fuzz_gif /
cp ./target/release/fuzz_guess /
cp ./target/release/fuzz_hdr /
cp ./target/release/fuzz_ico /
cp ./target/release/fuzz_jpeg /
cp ./target/release/fuzz_png /
cp ./target/release/fuzz_tga /
cp ./target/release/fuzz_tiff /
