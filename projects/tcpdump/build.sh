#!/bin/bash -eu
#
# Copyright (C) 2023 ISP RAS
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

if [[ $CONFIG = "libfuzzer" ]]
then
    export CC="clang"
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
    export LINK_FLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero\
                       -I/libpcap -I/tcpdump ../pretty_print_packet.c -o ../pretty_print_packet_fuzz\
                       /libpcap/libpcap.a /tcpdump/libnetdissect.a"
fi

if [[ $CONFIG = "afl" ]]
then
    export CC="afl-clang-fast"
    export CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
    export LINK_FLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero\
                       -I/libpcap -I/tcpdump ../pretty_print_packet.c -o ../pretty_print_packet_afl\
                       /libpcap/libpcap.a /tcpdump/libnetdissect.a"
fi

if [[ $CONFIG = "sydr" ]]
then
    export CC="clang"
    export CFLAGS="-g"
    export LINK_FLAGS="$CFLAGS -I/libpcap -I/tcpdump -DSYDR ../pretty_print_packet.c -o ../pretty_print_packet_sydr\
                       /libpcap/libpcap.a /tcpdump/libnetdissect.a /main.o"
    $CC $CFLAGS -c -o /main.o /main.c
fi

if [[ $CONFIG = "coverage" ]]
then
    export CC="clang"
    export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
    export LINK_FLAGS="$CFLAGS -I/libpcap -I/tcpdump -DSYDR ../pretty_print_packet.c -o ../pretty_print_packet_cov\
                       /libpcap/libpcap.a /tcpdump/libnetdissect.a /main.o"
    $CC $CFLAGS -c -o /main.o /main.c
fi

cd /libpcap
echo "build libpcap"
./autogen.sh
./configure CC="$CC" CFLAGS="$CFLAGS"
make clean
make -j`nproc`

cd /tcpdump
echo "build tcpdump"
./autogen.sh
./configure CC="$CC" CFLAGS="$CFLAGS"
make clean
make -j`nproc`

$CC $LINK_FLAGS
