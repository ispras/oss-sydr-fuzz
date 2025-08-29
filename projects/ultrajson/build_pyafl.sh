#!/bin/bash -eu
# Copyright 2020 Google Inc.
# Modifications copyright (C) 2025 ISP RAS
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

pip install testresources
pip install -U pip setuptools wheel
pip install python-afl

export CC="afl-clang-fast"
export CFLAGS="-fsanitize=address -Wl,-rpath=/usr/lib/clang/18.1.8/lib/linux/"
export CXX="clang++"
export CXXFLAGS="-fsanitize=address -Wl,-rpath=/usr/lib/clang/18.1.8/lib/linux/"
export LDFLAGS="/usr/local/lib/afl/afl-compiler-rt.o /usr/lib/clang/18.1.8/lib/linux/libclang_rt.asan-x86_64.so"
export LDSHARED="clang -shared"

pip3 install --ignore-installed .
