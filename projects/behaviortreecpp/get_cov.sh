#!/bin/bash -eu
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

mkdir -p /coverage/ && cd /coverage/
mkdir -p reports/

for fuzzer in script bb bt; do
    mkdir -p "${fuzzer}_fuzzer/" && cd "${fuzzer}_fuzzer/"
    mkdir -p "${fuzzer}_raw/" && cd "${fuzzer}_raw/"
    for file in "/${fuzzer}_corpus"/*; do
        LLVM_PROFILE_FILE=./$(basename "$file").profraw /${fuzzer}_fuzzer_cov  "$file";
    done

    cd .. && find "${fuzzer}_raw/" -name '*.profraw' > "${fuzzer}_cov.lst"
    llvm-profdata merge --input-files="${fuzzer}_cov.lst" -o "${fuzzer}_cov.profdata"

    llvm-cov export /${fuzzer}_fuzzer_cov -instr-profile "${fuzzer}_cov.profdata" -format=lcov > "${fuzzer}_cov.lcov"
    genhtml -o "${fuzzer}_cov_html" "${fuzzer}_cov.lcov"
    cp -rf "${fuzzer}_cov_html" "/coverage/reports/${fuzzer}_cov_html"
    cd /coverage/
done
