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

# Build LibAFL-DiFuzz save target.
cd /xlnt
rm -rf build && mkdir build && cd build

cmake -DSTATIC=ON -DTESTS=OFF \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    ..
CMAKE_BUILD_PARALLEL_LEVEL=$(nproc) cmake --build .

$CC $CXXFLAGS /opt/StandaloneFuzzTargetMain.c -c -o main.o
$CXX $CXXFLAGS -I/xlnt/include -I/xlnt/third-party/libstudxml -O2 -o ./save_libafl main.o ../save.cc ./source/libxlnt.a
