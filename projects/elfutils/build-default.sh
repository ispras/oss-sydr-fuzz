#!/usr/bin/env bash

# Copyright 2026 ISP RAS
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

set -eux

function aflpp() {
    local cc='afl-clang-fast'

    CC=$cc CXX="${cc}++" $BUILD_SH all /aflpp 1
}

function lf() {
    $BUILD_SH all /libfuzzer 1 
}

function cov() {
    local flags="-fprofile-instr-generate -fcoverage-mapping"

    CFLAGS=$flags CXXFLAGS=$flags $BUILD_SH all /cov 0
}

function sydr() {
    $BUILD_SH all /sydr 0 
}

aflpp
lf
cov
sydr
