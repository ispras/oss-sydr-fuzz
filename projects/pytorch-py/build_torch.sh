#!/bin/bash
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

set -e

cd /pytorch

# Build PyTorch libraries.
CC=clang
CXX=clang++
CFLAGS="-fPIC -g -fsanitize=fuzzer-no-link,address"
CXXFLAGS=$CFLAGS

CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS MAX_JOBS=$(( $(nproc) / 2 )) USE_ITT=0 USE_FBGEMM=0 BUILD_BINARY=1 USE_STATIC_MKL=1 \
    USE_DISTRIBUTED=1 USE_MPI=0 TP_BUILD_LIBUV=1 USE_TENSORPIPE=1 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=0 BUILD_TEST=0 \
    BUILD_SHARED_LIBS=ON BUILD_BINARY=OFF USE_OPENMP=0 USE_MKLDNN=0 \
    python3 setup.py bdist_wheel

cd /
WHL_PACKAGE=$(find /pytorch -name '*.whl')
python3 -m pip install ${WHL_PACKAGE}
