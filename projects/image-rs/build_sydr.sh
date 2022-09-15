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

cargo build
cp /image/fuzz/target/debug/sydr_script_bmp /
cp /image/fuzz/target/debug/sydr_script_exr /
cp /image/fuzz/target/debug/sydr_script_gif /
cp /image/fuzz/target/debug/sydr_script_guess /
cp /image/fuzz/target/debug/sydr_script_hdr /
cp /image/fuzz/target/debug/sydr_script_ico /
cp /image/fuzz/target/debug/sydr_script_jpeg /
cp /image/fuzz/target/debug/sydr_script_png /
cp /image/fuzz/target/debug/sydr_script_pnm /
cp /image/fuzz/target/debug/sydr_script_tga /
cp /image/fuzz/target/debug/sydr_script_tiff /
cp /image/fuzz/target/debug/sydr_script_webp /
