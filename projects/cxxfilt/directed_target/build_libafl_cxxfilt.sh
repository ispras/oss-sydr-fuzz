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

# Build LibAFL-DiFuzz cxxfilt target.
cd /cxxfilt-CVE-2016-4487
rm -rf build && mkdir -p build/temp

export ADDITIONAL="-D_FORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error"

cd build; CFLAGS="$ADDITIONAL $CFLAGS" CXXFLAGS="$ADDITIONAL $CXXFLAGS" LDFLAGS="-ldl -lutil" ../configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld
make clean; make
