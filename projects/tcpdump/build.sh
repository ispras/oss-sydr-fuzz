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

#Build targets for libfuzzer
if [[ $CONFIG = "libfuzzer" ]]
then
    export CC="clang"
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
    export TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
    export LINK_FLAGS="$TARGET_CFLAGS -I/libpcap -I/tcpdump ../load_sydr_packet.c -o ../fuzzer_packet\
                       /libpcap/libpcap.a /tcpdump/libnetdissect.a"
fi

if [[ $CONFIG = "afl" ]]
then
    cd /libpcap && make clean
    cd /tcpdump && make clean
    export CC="afl-clang-fast"
    export CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
    export TARGET_CFLAGS="-g -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
    export LINK_FLAGS="$TARGET_CFLAGS -I/libpcap -I/tcpdump ../load_sydr_packet.c -o ../afl_packet\
                       /libpcap/libpcap.a /tcpdump/libnetdissect.a"
fi

if [[ $CONFIG = "sydr" ]]
then
    cd /libpcap && make clean
    cd /tcpdump && make clean
    export CC="clang"
    export CFLAGS="-g"
    export LINK_FLAGS="$CFLAGS -I/libpcap -I/tcpdump ../load_sydr_packet.c -o ../sydr_packet\
                       /libpcap/libpcap.a /tcpdump/libnetdissect.a /main.o"
    $CC $CFLAGS -c -o /main.o /opt/StandaloneFuzzTargetMain.c
fi

if [[ $CONFIG = "coverage" ]]
then
    cd /libpcap && make clean
    cd /tcpdump && make clean
    export CC="clang"
    export CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
    export LINK_FLAGS="$CFLAGS -I/libpcap -I/tcpdump ../load_sydr_packet.c -o ../cov_packet\
                       /libpcap/libpcap.a /tcpdump/libnetdissect.a /main.o"
    $CC $CFLAGS -c -o main.o /opt/StandaloneFuzzTargetMain.c
fi

cd /libpcap
echo "build libpcap"
./autogen.sh
./configure CC="$CC" CFLAGS="$CFLAGS"
make -j`nproc`

cd /tcpdump
echo "build tcpdump"
./autogen.sh
./configure CC="$CC" CFLAGS="$CFLAGS"
make -j`nproc`

$CC $LINK_FLAGS
