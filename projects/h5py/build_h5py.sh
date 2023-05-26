#!/bin/bash -eu
# Copyright 2023 Google LLC.
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

cp -r $(find /hdf5 -name src ! -path "/hdf5/src") /hdf5/src
find /hdf5/src -mindepth 2 -type f -exec mv -t /hdf5/src -n '{}' +

export CC=clang
export CXX=clang++
export CFLAGS="-g -fsanitize=fuzzer-no-link,address"
export CXXFLAGS="-g -fsanitize=fuzzer-no-link,address"

CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS MAX_JOBS=$(nproc) BUILD_BINARY=1 \
    H5PY_SETUP_REQUIRES=0 HDF5_LIBDIR=/hdf5/build-dir/bin/ HDF5_INCLUDEDIR=/hdf5/src \
    ASAN_OPTIONS="detect_leaks=0" UBSAN_OPTIONS="abort_on_error=0" \
    LD_PRELOAD=$(find /usr/local/lib/ -name 'asan_with_fuzzer.so') \
    python3 setup.py build

CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS MAX_JOBS=$(nproc) BUILD_BINARY=1 \
    H5PY_SETUP_REQUIRES=0 HDF5_LIBDIR=/hdf5/build-dir/bin/ HDF5_INCLUDEDIR=/hdf5/src \
    ASAN_OPTIONS="detect_leaks=0" UBSAN_OPTIONS="abort_on_error=0" \
    LD_PRELOAD=$(find /usr/local/lib/ -name 'asan_with_fuzzer.so') \
    python3 -m pip install . --no-binary=h5py
