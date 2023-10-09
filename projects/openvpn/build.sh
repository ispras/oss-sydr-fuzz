#!/bin/bash -eu
# Copyright 2021 Google LLC
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

export BASE="/openvpn/src/openvpn"
export MAIN_LINK=""

apply_sed_changes() {
  sed -i 's/read(/fuzz_read(/g' $BASE/console_systemd.c
  sed -i 's/fgets(/fuzz_fgets(/g' $BASE/console_builtin.c
  sed -i 's/fgets(/fuzz_fgets(/g' $BASE/misc.c
  sed -i 's/#include "forward.h"/#include "fuzz_header.h"\n#include "forward.h"/g' $BASE/proxy.c
  sed -i 's/select(/fuzz_select(/g' $BASE/proxy.c
  sed -i 's/send(/fuzz_send(/g' $BASE/proxy.c
  sed -i 's/recv(/fuzz_recv(/g' $BASE/proxy.c
  sed -i 's/isatty/fuzz_isatty/g' $BASE/console_builtin.c

  sed -i 's/fopen/fuzz_fopen/g' $BASE/console_builtin.c
  sed -i 's/fclose/fuzz_fclose/g' $BASE/console_builtin.c

  sed -i 's/sendto/fuzz_sendto/g' $BASE/socket.h
  sed -i 's/#include "misc.h"/#include "misc.h"\nextern size_t fuzz_sendto(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen);/g' $BASE/socket.h

  sed -i 's/fp = (flags/fp = stdout;\n\/\//g' $BASE/error.c

  sed -i 's/crypto_msg(M_FATAL/crypto_msg(M_WARN/g' $BASE/crypto_openssl.c
  sed -i 's/msg(M_FATAL, \"Cipher/return;msg(M_FATAL, \"Cipher/g' $BASE/crypto.c
  sed -i 's/msg(M_FATAL/msg(M_WARN/g' $BASE/crypto.c

  sed -i 's/= write/= fuzz_write/g' $BASE/packet_id.c
}

cd openvpn

if [[ $CONFIG = "libfuzzer" ]]
then
  export CC="clang"
  export CXX="clang++"
  export CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
  export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
  export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
  export SUFFIX="fuzz"

  # Changes in the code so we can fuzz it.
  git apply /crypto_patch.txt

  echo "" >> $BASE/openvpn.c
  echo "#include \"fake_fuzz_header.h\"" >> $BASE/openvpn.c
  echo "ssize_t fuzz_get_random_data(void *buf, size_t len) { return 0; }" >> $BASE/fake_fuzz_header.h
  echo "int fuzz_success;" >> $BASE/fake_fuzz_header.h

  # Apply hooking changes
  apply_sed_changes
fi

if [[ $CONFIG = "afl" ]]
then
  export CC="afl-clang-fast"
  export CXX="afl-clang-fast++"
  export CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
  export CXXFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
  export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
  export SUFFIX="afl"
fi

if [[ $CONFIG = "sydr" ]]
then
      export CC=clang
      export CXX=clang++
      export CFLAGS="-g"
      export CXXFLAGS="-g"
      export LINK_FLAGS="$CFLAGS"
      export SUFFIX="sydr"
fi

if [[ $CONFIG = "coverage" ]]
then
      export CC=clang
      export CXX=clang++
      export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
      export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
      export LINK_FLAGS="$CFLAGS"
      export SUFFIX="cov"
fi

# Build openvpn
rm -rf /openvpn/src/openvpn/*.o
autoreconf -ivf
./configure --disable-lz4 --with-crypto-library=openssl OPENSSL_LIBS="-L/usr/local/ssl/ -lssl -lcrypto" OPENSSL_CFLAGS="-I/usr/local/ssl/include/"
make

# Make openvpn object files into a library we can link fuzzers to
cd src/openvpn
rm openvpn.o
ar r libopenvpn.a *.o

# Compile our fuzz helper
$CXX $CXXFLAGS -g -c /fuzz_randomizer.cpp -o /fuzz_randomizer.o

# Object file main.o for sydr and coverage build
if [[ $CONFIG = "sydr" || $CONFIG = "coverage" ]]
then
    $CC $CFLAGS -c -o /main.o /opt/StandaloneFuzzTargetMain.c
    export MAIN_LINK="/main.o"
fi

# Compile the fuzzers
for fuzzname in dhcp misc base64 proxy buffer route packet_id mroute list verify_cert; do
    $CC -DHAVE_CONFIG_H -I. -I../.. -I../../include -I../../src/compat -I/usr/include/libnl3/ \
      -DPLUGIN_LIBDIR=\"/usr/local/lib/openvpn/plugins\" -std=c99 $CFLAGS \
      -c /fuzz_${fuzzname}.c -o /fuzz_${fuzzname}.o

    # Link with CXX
    $CXX $LINK_FLAGS /fuzz_${fuzzname}.o -o /fuzz_${fuzzname}_$SUFFIX /fuzz_randomizer.o \
        libopenvpn.a ../../src/compat/.libs/libcompat.a /usr/lib/x86_64-linux-gnu/libnsl.a \
        /usr/lib/x86_64-linux-gnu/libresolv.a /usr/lib/x86_64-linux-gnu/liblzo2.a \
        -lssl -lcrypto -ldl -l:libnl-3.a -l:libnl-genl-3.a -lcap-ng -lpthread $MAIN_LINK
done

# Get corpus
if [[ $CONFIG = "coverage" ]]
then
  mkdir /corpus
  cd /boringssl/fuzz/
  cp -R -f -n *_corpus/* /corpus
  cd /corpus && find -type f -size +1M -delete
fi
