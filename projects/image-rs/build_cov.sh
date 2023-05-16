#!/bin/bash -eu
# Copyright 2022 ISP RAS
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
export RUSTFLAGS="-C instrument-coverage"

cargo build
cp /image/fuzz/target/debug/sydr_script_bmp /cov_script_bmp
cp /image/fuzz/target/debug/sydr_script_exr /cov_script_exr
cp /image/fuzz/target/debug/sydr_script_gif /cov_script_gif
cp /image/fuzz/target/debug/sydr_script_guess /cov_script_guess
cp /image/fuzz/target/debug/sydr_script_hdr /cov_script_hdr
cp /image/fuzz/target/debug/sydr_script_ico /cov_script_ico
cp /image/fuzz/target/debug/sydr_script_jpeg /cov_script_jpeg
cp /image/fuzz/target/debug/sydr_script_png /cov_script_png
cp /image/fuzz/target/debug/sydr_script_pnm /cov_script_pnm
cp /image/fuzz/target/debug/sydr_script_tga /cov_script_tga
cp /image/fuzz/target/debug/sydr_script_tiff /cov_script_tiff
cp /image/fuzz/target/debug/sydr_script_webp /cov_script_webp
