#!/bin/bash -eu
# Copyright 2017 Google Inc.
# Modifications copyright (C) 2024 ISP RAS
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

git apply ssh.patch

# Fix AFL++ build for sig_fuzz
sed -i '3140s/no]) ]/no])\n enable_nistp521=1 ]/' configure.ac
# Add extra algorithms for kex_fuzz
git apply kex_fuzz.patch

EXTRA_CFLAGS="-DCIPHER_NONE_AVAIL=1"
STATIC_CRYPTO="-Wl,-Bstatic -lcrypto -Wl,-Bdynamic"
SK_NULL=ssh-sk-null.o
SK_DUMMY=sk-dummy.o
AUTH_PUBKEY=auth2-pubkeyfile.o
SSHD_SERV=""

# Build libFuzzer fuzz targets.

export CC="clang"
export CXX="clang++"
export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,undefined,null,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,undefined,null,float-divide-by-zero"

autoreconf

./configure \
    --without-hardening \
    --without-zlib-version-check \
    --with-cflags="-DWITH_XMSS=1" \
    --with-cflags-after="$CFLAGS" \
    --with-ldflags-after="-g $CFLAGS" \
    --with-sandbox=no
make -j$(nproc) all

$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        regress/misc/fuzz-harness/ssh-sk-null.cc -o ssh-sk-null.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        -DSK_DUMMY_INTEGRATE=1 regress/misc/sk-dummy/sk-dummy.c -o sk-dummy.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        regress/misc/fuzz-harness/agent_fuzz_helper.c -o agent_fuzz_helper.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c -DENABLE_SK_INTERNAL=1 ssh-sk.c -o ssh-sk.o

mkdir /lf

for fuzz_target in regress/misc/fuzz-harness/*_fuzz.cc
do
    echo "Compiling $fuzz_target"
    filename=$(basename -- "$fuzz_target")
    filename="${filename%.*}"

    AUTH_PUBKEY=""
    if [[ $filename == "agent_fuzz" || $filename == "authkeys_fuzz" || $filename == "lsc_fuzz" ]]; then
        if [[  $filename == "authkeys_fuzz" ]]; then
            AUTH_PUBKEY=auth2-pubkeyfile.o
            continue
        fi
        SK_NULL=""
        SSH_SK=ssh-sk.o
        SK_DUMMY=sk-dummy.o
        if [[ $filename == "lsc_fuzz" ]]; then
            SSHD_SERV="groupaccess.o auth2-methods.o servconf.o"
            AUTH_PUBKEY=""
        fi
    else
        SSHD_SERV=""
        SK_NULL=ssh-sk-null.o
        SSH_SK=""
        SK_DUMMY=""
    fi
    $CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
        $fuzz_target -o /lf/$filename\_lf $SK_DUMMY agent_fuzz_helper.o $SSH_SK \
        auth-options.o $AUTH_PUBKEY $SSHD_SERV sshsig.o -lssh -lz -lopenbsd-compat $SK_NULL $STATIC_CRYPTO
done

# Build AFL++ fuzz targets.

export CC="afl-clang-fast"
export CXX="afl-clang-fast++"
export CFLAGS="-g -fsanitize=address,bounds,undefined,null,float-divide-by-zero"
export CXXFLAGS="-g -fsanitize=fuzzer,address,bounds,undefined,null,float-divide-by-zero"

autoreconf
make clean

./configure \
    --without-hardening \
    --without-zlib-version-check \
    --with-cflags="-DWITH_XMSS=1" \
    --with-cflags-after="$CFLAGS" \
    --with-ldflags-after="-g $CFLAGS" \
    --with-sandbox=no
make -j$(nproc) all

$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        regress/misc/fuzz-harness/ssh-sk-null.cc -o ssh-sk-null.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        -DSK_DUMMY_INTEGRATE=1 regress/misc/sk-dummy/sk-dummy.c -o sk-dummy.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        regress/misc/fuzz-harness/agent_fuzz_helper.c -o agent_fuzz_helper.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c -DENABLE_SK_INTERNAL=1 ssh-sk.c -o ssh-sk.o

mkdir /afl

for fuzz_target in regress/misc/fuzz-harness/*_fuzz.cc
do
    echo "Compiling $fuzz_target"
    filename=$(basename -- "$fuzz_target")
    filename="${filename%.*}"

    AUTH_PUBKEY=""
    if [[ $filename == "agent_fuzz" || $filename == "authkeys_fuzz" || $filename == "lsc_fuzz" ]]; then
        if [[  $filename == "authkeys_fuzz" ]]; then
            AUTH_PUBKEY=auth2-pubkeyfile.o
            continue
        fi
        SK_NULL=""
        SSH_SK=ssh-sk.o
        SK_DUMMY=sk-dummy.o
        if [[ $filename == "lsc_fuzz" ]]; then
            SSHD_SERV="groupaccess.o auth2-methods.o servconf.o"
            AUTH_PUBKEY=""
        fi
    else
        SSHD_SERV=""
        SK_NULL=ssh-sk-null.o
        SSH_SK=""
        SK_DUMMY=""
    fi
    $CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
        $fuzz_target -o /afl/$filename\_afl $SK_DUMMY agent_fuzz_helper.o $SSH_SK \
        auth-options.o $AUTH_PUBKEY $SSHD_SERV sshsig.o -lssh -lz -lopenbsd-compat $SK_NULL $STATIC_CRYPTO
done

# Build Sydr fuzz targets.

export CC="clang"
export CXX="clang++"
export CFLAGS="-g"
export CXXFLAGS="-g"

autoreconf
make clean

./configure \
    --without-hardening \
    --without-zlib-version-check \
    --with-cflags="-DWITH_XMSS=1" \
    --with-cflags-after="$CFLAGS" \
    --with-ldflags-after="-g $CFLAGS" \
    --with-sandbox=no
make -j$(nproc) all

$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        regress/misc/fuzz-harness/ssh-sk-null.cc -o ssh-sk-null.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        -DSK_DUMMY_INTEGRATE=1 regress/misc/sk-dummy/sk-dummy.c -o sk-dummy.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        regress/misc/fuzz-harness/agent_fuzz_helper.c -o agent_fuzz_helper.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c -DENABLE_SK_INTERNAL=1 ssh-sk.c -o ssh-sk.o

mkdir /sydr

for fuzz_target in regress/misc/fuzz-harness/*_fuzz.cc
do
    echo "Compiling $fuzz_target"
    filename=$(basename -- "$fuzz_target")
    filename="${filename%.*}"

    AUTH_PUBKEY=""
    if [[ $filename == "agent_fuzz" || $filename == "authkeys_fuzz" || $filename == "lsc_fuzz" ]]; then
        if [[  $filename == "authkeys_fuzz" ]]; then
            AUTH_PUBKEY=auth2-pubkeyfile.o
            continue
        fi
        if [[  $filename == "lsc_fuzz" ]]; then
            SSHD_SERV="groupaccess.o auth2-methods.o servconf.o"
            AUTH_PUBKEY=""
        fi
        SK_NULL=""
        SSH_SK=ssh-sk.o
        SK_DUMMY=sk-dummy.o
    else
        SSHD_SERV=""
        SK_NULL=ssh-sk-null.o
        SSH_SK=""
        SK_DUMMY=""
    fi
    $CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
        main.o $fuzz_target -o /sydr/$filename\_sydr $SK_DUMMY agent_fuzz_helper.o \
        $SSH_SK auth-options.o $AUTH_PUBKEY $SSHD_SERV sshsig.o -lssh -lz -lopenbsd-compat \
        $SK_NULL -lpthread -ldl $STATIC_CRYPTO
done

# Build coverage targets.

export CC="clang"
export CXX="clang++"
export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"

autoreconf
make clean

./configure \
    --without-hardening \
    --without-zlib-version-check \
    --with-cflags="-DWITH_XMSS=1" \
    --with-cflags-after="$CFLAGS" \
    --with-ldflags-after="-g $CFLAGS" \
    --with-sandbox=no
make -j$(nproc) all

$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        regress/misc/fuzz-harness/ssh-sk-null.cc -o ssh-sk-null.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        -DSK_DUMMY_INTEGRATE=1 regress/misc/sk-dummy/sk-dummy.c -o sk-dummy.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c \
        regress/misc/fuzz-harness/agent_fuzz_helper.c -o agent_fuzz_helper.o
$CC $CFLAGS $EXTRA_CFLAGS -I. -g -c -DENABLE_SK_INTERNAL=1 ssh-sk.c -o ssh-sk.o

mkdir /cov

for fuzz_target in regress/misc/fuzz-harness/*_fuzz.cc
do
    echo "Compiling $fuzz_target"
    filename=$(basename -- "$fuzz_target")
    filename="${filename%.*}"

    AUTH_PUBKEY=""
    if [[ $filename == "agent_fuzz" || $filename == "authkeys_fuzz" || $filename == "lsc_fuzz" ]]; then
        if [[  $filename == "authkeys_fuzz" ]]; then
            AUTH_PUBKEY=auth2-pubkeyfile.o
            continue
        fi
        SK_NULL=""
        SSH_SK=ssh-sk.o
        SK_DUMMY=sk-dummy.o
        if [[ $filename == "lsc_fuzz" ]]; then
            SSHD_SERV="groupaccess.o auth2-methods.o servconf.o"
            AUTH_PUBKEY=""
        fi
    else
        SSHD_SERV=""
        SK_NULL=ssh-sk-null.o
        SSH_SK=""
        SK_DUMMY=""
    fi
    $CXX $CXXFLAGS -std=c++11 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat -g \
        main.o $fuzz_target -o /cov/$filename\_cov $SK_DUMMY agent_fuzz_helper.o \
        $SSH_SK auth-options.o $AUTH_PUBKEY $SSHD_SERV sshsig.o -lssh -lz -lopenbsd-compat \
        $SK_NULL -lpthread -ldl $STATIC_CRYPTO
done

# Prepare seed corpora
CASES="/openssh-fuzz-cases"
(set -e ; mkdir /key_corpus       ; cd ${CASES}/key       ; find . -type f -exec cp {} /key_corpus \;)
(set -e ; mkdir /privkey_corpus   ; cd ${CASES}/privkey   ; find . -type f -exec cp {} /privkey_corpus \;)
(set -e ; mkdir /sig_corpus       ; cd ${CASES}/sig       ; find . -type f -exec cp {} /sig_corpus \;)
(set -e ; mkdir /authopt_corpus   ; cd ${CASES}/authopt   ; find . -type f -exec cp {} /authopt_corpus \;)
(set -e ; mkdir /sshsig_corpus    ; cd ${CASES}/sshsig    ; find . -type f -exec cp {} /sshsig_corpus \;)
(set -e ; mkdir /sshsigopt_corpus ; cd ${CASES}/sshsigopt ; find . -type f -exec cp {} /sshsigopt_corpus \;)
(set -e ; mkdir /kex_corpus       ; cd ${CASES}/kex       ; find . -type f -exec cp {} /kex_corpus \;)
(set -e ; mkdir /agent_corpus     ; cd ${CASES}/agent     ; find . -type f -exec cp {} /agent_corpus \;)
(set -e ; mkdir /lsc_corpus       ; cd /openssh           ; find . -name "sshd_config" -exec cp {} /lsc_corpus \;)
