#!/bin/bash -ex
# Copyright 2019 Google Inc.
# Modifications copyright (C) 2023 ISP RAS
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
echo "[x] Prerequisites"
tar -xvzf pcre2-10.39.tar.gz
tar -xvzf lz4-1.9.2.tar.gz
tar -xvzf jansson-2.12.tar.gz

echo "[x] Libfuzzer stage"
export CC=clang
export CXX=clang++
export ac_cv_func_malloc_0_nonnull=yes
export ac_cv_func_realloc_0_nonnull=yes
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
export LDFLAGS="-fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-trace-compares"
export RUSTFLAGS="$RUSTFLAGS -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth -Ccodegen-units=1 -Cdebug-assertions=yes"
export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"

(
cd pcre2-10.39
./configure --disable-shared
make -j$(nproc) clean
make -j$(nproc) all
make -j$(nproc) install
)

(
cd lz4-1.9.2
make liblz4.a
cp lib/liblz4.a /usr/local/lib/
cp lib/lz4*.h /usr/local/include/
)

(
cd jansson-2.12
./configure --disable-shared
make -j$(nproc)
make install
)

(
cd fuzzpcap
mkdir build
cd build
cmake ..
make install
)

(
cp -r libhtp suricata && cd suricata

sh autogen.sh
./src/tests/fuzz/oss-fuzz-configure.sh && make -j$(nproc)

mkdir libfuzzer

./src/suricata --list-app-layer-protos | tail -n +2 | while read i; do cp src/fuzz_applayerparserparse libfuzzer/fuzz_applayerparserparse_$i; done

mv libfuzzer/fuzz_applayerparserparse_http libfuzzer/fuzz_applayerparserparse_http1

cp src/fuzz_applayerprotodetectgetproto libfuzzer/fuzz_applayerprotodetectgetproto
cp src/fuzz_mimedecparseline libfuzzer/fuzz_mimedecparseline
cp src/fuzz_predefpcap_aware libfuzzer/fuzz_predefpcap_aware
cp src/fuzz_sigpcap_aware libfuzzer/fuzz_sigpcap_aware

make clean
)

echo "[x] AFL++ stage"
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export ac_cv_func_malloc_0_nonnull=yes
export ac_cv_func_realloc_0_nonnull=yes
export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
export RUSTFLAGS="-C debug-assertions -C overflow_checks -C passes=sancov-module -C codegen-units=1 -C llvm-args=-sanitizer-coverage-level=3 -C llvm-args=-sanitizer-coverage-trace-pc-guard -C llvm-args=-sanitizer-coverage-prune-blocks=0 -C opt-level=3 -C target-cpu=native -Clink-arg=-fuse-ld=gold"

(
cd pcre2-10.39
./configure --disable-shared
make -j$(nproc) clean
make -j$(nproc) all
make -j$(nproc) install
)

(
cd lz4-1.9.2
make liblz4.a
cp lib/liblz4.a /usr/local/lib/
cp lib/lz4*.h /usr/local/include/
)

(
cd jansson-2.12
make clean
./configure --disable-shared
make -j$(nproc)
make install
)

(
cd fuzzpcap
rm -rf build
mkdir build
cd build
cmake ..
make install
)

(
cp -r libhtp suricata && cd suricata
sh autogen.sh
./src/tests/fuzz/oss-fuzz-configure.sh && make -j$(nproc)

mkdir afl

./src/suricata --list-app-layer-protos | tail -n +2 | while read i; do cp src/fuzz_applayerparserparse afl/fuzz_applayerparserparse_$i; done

mv afl/fuzz_applayerparserparse_http afl/fuzz_applayerparserparse_http1

cp src/fuzz_applayerprotodetectgetproto afl/fuzz_applayerprotodetectgetproto
cp src/fuzz_mimedecparseline afl/fuzz_mimedecparseline
cp src/fuzz_predefpcap_aware afl/fuzz_predefpcap_aware
cp src/fuzz_sigpcap_aware afl/fuzz_sigpcap_aware
make clean
)

unset CFLAGS
unset CXXFLAGS
unset LDFLAGS
unset RUSTFLAGS

echo "[x] Sydr stage"
export CC=clang

(
cd pcre2-10.39
./configure --disable-shared
make -j$(nproc) clean
make -j$(nproc) all
make -j$(nproc) install
)

(
cd lz4-1.9.2
make clean
make liblz4.a
cp lib/liblz4.a /usr/local/lib/
cp lib/lz4*.h /usr/local/include/
)

(
cd jansson-2.12
make clean
./configure --disable-shared
make -j$(nproc)
make install
)

(
cd fuzzpcap
rm -rf build
mkdir build
cd build
cmake ..
make install
)

(
cp -r libhtp suricata && cd suricata

sed -i 's/fuzz_applayerparserparse.c/sydr_applayerparserparse.c/g' src/Makefile.am
sed -i 's/fuzz_applayerparserparse_LDFLAGS/PASS/g' src/Makefile.am
sed -i 's/fuzz_applayerprotodetectgetproto.c/sydr_applayerprotodetectgetproto.c/g' src/Makefile.am
sed -i 's/fuzz_applayerprotodetectgetproto_LDFLAGS/PASS/g' src/Makefile.am
sed -i 's/fuzz_mimedecparseline.c/sydr_mimedecparseline.c/g' src/Makefile.am
sed -i 's/fuzz_mimedecparseline_LDFLAGS/PASS/g' src/Makefile.am
sed -i 's/fuzz_sigpcap_aware.c/sydr_sigpcap_aware.c/g' src/Makefile.am
sed -i 's/fuzz_sigpcap_aware_LDFLAGS/PASS/g' src/Makefile.am
sed -i 's/fuzz_predefpcap_aware.c/sydr_predefpcap_aware.c/g' src/Makefile.am
sed -i 's/fuzz_predefpcap_aware_LDFLAGS/PASS/g' src/Makefile.am

./src/tests/fuzz/oss-fuzz-configure.sh && make -j$(nproc)

mkdir sydr
sh autogen.sh
./src/suricata --list-app-layer-protos | tail -n +2 | while read i; do cp src/fuzz_applayerparserparse sydr/fuzz_applayerparserparse_$i; done

mv sydr/fuzz_applayerparserparse_http sydr/fuzz_applayerparserparse_http1

cp src/fuzz_applayerprotodetectgetproto sydr/fuzz_applayerprotodetectgetproto
cp src/fuzz_mimedecparseline sydr/fuzz_mimedecparseline
cp src/fuzz_predefpcap_aware sydr/fuzz_predefpcap_aware
cp src/fuzz_sigpcap_aware sydr/fuzz_sigpcap_aware
make clean
)

echo "[x] Coverage stage"
export CC=clang
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
export RUSTFLAGS="-Cinstrument-coverage"
export ac_cv_func_malloc_0_nonnull=yes
export ac_cv_func_realloc_0_nonnull=yes

(
cd pcre2-10.39
./configure --disable-shared
make -j$(nproc) clean
make -j$(nproc) all
make -j$(nproc) install
)

(
cd lz4-1.9.2
make clean
make liblz4.a
cp lib/liblz4.a /usr/local/lib/
cp lib/lz4*.h /usr/local/include/
)

(
cd jansson-2.12
make clean
./configure --disable-shared
make -j$(nproc)
make install
)

(
cd fuzzpcap
rm -rf build
mkdir build
cd build
cmake ..
make install
)

(
cp -r libhtp suricata && cd suricata
sh autogen.sh
./src/tests/fuzz/oss-fuzz-configure.sh && make -j$(nproc)

mkdir cover

./src/suricata --list-app-layer-protos | tail -n +2 | while read i; do cp src/fuzz_applayerparserparse cover/fuzz_applayerparserparse_$i; done

mv cover/fuzz_applayerparserparse_http cover/fuzz_applayerparserparse_http1

cp src/fuzz_applayerprotodetectgetproto cover/fuzz_applayerprotodetectgetproto
cp src/fuzz_mimedecparseline cover/fuzz_mimedecparseline
cp src/fuzz_predefpcap_aware cover/fuzz_predefpcap_aware
cp src/fuzz_sigpcap_aware cover/fuzz_sigpcap_aware
make clean
)

