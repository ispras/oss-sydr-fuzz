#!/bin/bash -eu
# Copyright 2016 Google Inc.
# Modifications copyright (C) 2021 ISP RAS
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

mkdir /out
export CC="clang"
export CXX="clang++"
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,undefined,null,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,undefined,null,float-divide-by-zero"
PATH_TO_LIBFUZZER="$(find /usr/lib/clang -name libclang_rt.fuzzer-x86_64.a)"

CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]
then
  CONFIGURE_FLAGS="no-asm"
fi

./config --debug enable-fuzz-libfuzzer -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers --with-fuzzer-lib=$PATH_TO_LIBFUZZER $CFLAGS -fno-sanitize=alignment $CONFIGURE_FLAGS

make -j$(nproc) LDCMD="$CXX $CXXFLAGS"

fuzzers=$(find fuzz -executable -type f '!' -name \*.py '!' -name \*-test '!' -name \*.pl)
for f in $fuzzers; do
	fuzzer=$(basename $f)
	cp $f /out
done

# Build Sydr fuzz targets

export CFLAGS="-g"
export CXXFLAGS="-g"
make clean
./config --debug -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers $CFLAGS -fno-sanitize=alignment
make -j$(nproc) LDCMD="$CXX $CXXFLAGS"

targets=$(find fuzz -type f -name \*_sydr.c)
for target in $targets; do
	basename=$(basename $target)
        name=${basename%_*}
	echo "Build ${name} fuzz target for Sydr"
	clang -Iinclude -Ifuzz -pthread -m64 -fno-omit-frame-pointer -g -Wall -O0 -L. -DOPENSSL_BUILDING_OPENSSL -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -o /out/${name}_sydr ${target} fuzz/fuzz_rand.c -lssl -lcrypto -ldl -pthread
done

cp fuzz/oids.txt /out/asn1.dict
cp fuzz/oids.txt /out/x509.dict
