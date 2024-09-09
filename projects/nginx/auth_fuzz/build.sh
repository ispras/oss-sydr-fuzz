#!/bin/bash
# Copyright 2024 ISP RAS
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

# Make and install ansifilter
ANSIFILTER_SRC_DIR="/ansifilter"
cd ${ANSIFILTER_SRC_DIR}
env CC=clang CXX=clang++ make
make install
cd /
rm -rf ${ANSIFILTER_SRC_DIR}

# Make preeny
cd preeny
make
cd /

NGINX_DIR=$1
PATCHES_DIR=$2
BUILD_VARIANT=$3

# Function to check if a string is in an array
contains() {
    local e match="$1"
    shift
    for e; do [[ "$e" == "$match" ]] && return 0; done
    return 1
}

# Valid build variants
VALID_VARIANTS=("afl++" "sydr" "cov" "all")

# Check if the build variant is valid
if [ -z "$BUILD_VARIANT" ] || ! contains "$BUILD_VARIANT" "${VALID_VARIANTS[@]}"; then
    echo "Usage: $0 <NGINX_DIR> <PATCHES_DIR> <BUILD_VARIANT>"
    echo "Valid build variants: ${VALID_VARIANTS[*]}"
    exit 1
fi


# Save the launch directory
LAUNCH_DIR=$(pwd)


set -e

# Function to build and rename nginx
build_and_rename() {
    local suffix=$1

    make -j$(nproc)
    make install
    mv objs/nginx /http_auth$suffix
}

# Change to the NGINX directory
cd "$NGINX_DIR"


if [ "$BUILD_VARIANT" = "afl++" ] || [ "$BUILD_VARIANT" = "all" ]; then
    # Apply AFL++ patch
    patch -p1 < "$PATCHES_DIR/nginx_auth_afl++.patch"

    # Build AFL++ variant
    CC=afl-clang-fast CXX=afl-clang-fast++ auto/configure \
        --with-http_auth_request_module --with-select_module
    build_and_rename "_afl++"

    # Undo the AFL++ patch
    hg revert --all
fi


if [ "$BUILD_VARIANT" = "sydr" ] || [ "$BUILD_VARIANT" = "all" ]; then
    # Apply Sydr patch
    patch -p1 < "$PATCHES_DIR/nginx_auth_sydr.patch"

    # Build Sydr variant
    CC=clang CXX=clang++ auto/configure \
        --with-cc-opt="-g -fPIE" \
        --with-ld-opt="-g -fPIE" \
        --with-http_auth_request_module --with-select_module
    build_and_rename "_sydr"

    # Undo the Sydr patch
    hg revert --all
fi


if [ "$BUILD_VARIANT" = "cov" ] || [ "$BUILD_VARIANT" = "all" ]; then
    # Apply debug patch
    patch -p1 < "$PATCHES_DIR/nginx_auth_sydr.patch"

    # Build debug variant
    CC=clang CXX=clang++ auto/configure \
        --with-cc-opt="-fprofile-instr-generate -fcoverage-mapping -g -fPIE" \
        --with-ld-opt="-fprofile-instr-generate -fcoverage-mapping -g -fPIE" \
        --with-http_auth_request_module --with-select_module
    build_and_rename "_cov"

    # Undo the debug patch
    hg revert --all
fi


cd "$LAUNCH_DIR"

echo "Nginx variants built successfully."
