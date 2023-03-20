# Copyright 2023 ISP RAS
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

cd ntp-dev

git apply ../patch.diff

# build targets for AFL++

export CXX=afl-clang-fast++
export CXXFLAGS="-g -fsanitize=fuzzer,address,undefined"
export CC=afl-clang-fast
export CFLAGS="-g -fsanitize=fuzzer,address,undefined"

./bootstrap
./configure --enable-fuzztargets
make -j$(nproc)
cp tests/fuzz/fuzz_ntpd_receive /ntpd_receive_aflplusplus

# build targets for libFuzzer

export CXX=clang++
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined"
export CC=clang
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,undefined"

make clean
./configure --enable-fuzztargets
make -j$(nproc)
cp tests/fuzz/fuzz_ntpd_receive /ntpd_receive_libfuzzer

# build targets for Sydr

export CXXFLAGS="-g"
export CFLAGS="-g"
export LIB_FUZZING_ENGINE="."

make clean
./configure --enable-fuzztargets
make -j$(nproc)
cp tests/fuzz/fuzz_ntpd_receive /ntpd_receive_sydr

# build targets for llvm-cov

export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

make clean
./configure --enable-fuzztargets
make -j$(nproc)
cp tests/fuzz/fuzz_ntpd_receive /ntpd_receive_coverage


