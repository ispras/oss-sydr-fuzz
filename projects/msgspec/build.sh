#!/bin/bash -eu
# Copyright (C) 2023 ISP RAS
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

cd /tomli

pip3 install . 

cd /yaml-0.2.5

CC=clang CFLAGS="-g -fsanitize=fuzzer-no-link,address" ./configure

make install -j`nproc`

cd /PyYAML-5.3.1

CC=clang CFLAGS="-g -fsanitize=fuzzer-no-link,address" python3 setup.py --with-libyaml install

pip3 install --ignore-installed .

cd /msgspec

MSGSPEC_DEBUG=1 CC=clang CFLAGS="-g -fsanitize=fuzzer-no-link,address" LDSHARED="clang -shared" pip3 install .
