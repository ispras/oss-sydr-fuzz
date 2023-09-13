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

mkdir /custom_afl_cc
cd custom_afl_cc
git clone https://github.com/AFLplusplus/AFLplusplus.git && cd AFLplusplus
git checkout v4.08c && export CC=clang && export CXX=clang++ && \
	export CFLAGS="-DMAX_PARAMS_NUM=16384 -ldl" && export CXXFLAGS="-DMAX_PARAMS_NUM=16384 -ldl" && \
	export LD_LIBRARY_PATH="$(llvm-config --libdir)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" && make clean && \
	make distrib -j $(nproc)
