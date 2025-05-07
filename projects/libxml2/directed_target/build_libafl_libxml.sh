# Copyright 2025 ISP RAS
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

#!/bin/bash -eu

# Build LibAFL-DiFuzz libxml target.
cd /libxml2_ef709ce2
rm -rf build && mkdir -p build/temp

export LLVM_BINDIR="/usr/bin"
export ADDITIONAL="-g"

pyenv global 3.8

./autogen.sh; make distclean
cd build; CFLAGS="$ADDITIONAL $CFLAGS" CXXFLAGS="$ADDITIONAL $CXXFLAGS" ../configure --with-valid --disable-shared --prefix=`pwd`
make clean; make -j4

pyenv global 3.11
