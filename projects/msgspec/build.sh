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


python3 -m venv --system-site-packages /atherisVenv
python3 -m venv --system-site-packages /pyAflVenv

# prepare PythonAfl venv

source /pyAflVenv/bin/activate

pip install python-afl --ignore-installed
pip install coverage --ignore-installed
pip install testresources
pip install -U pip setuptools wheel

cd /tomli
pip3 install .
rm -rf build

cd /yaml-0.2.5
CC=afl-clang-fast ./configure
make install -j`nproc`

cd /PyYAML-5.3.1
CC=afl-clang-fast python3 setup.py --with-libyaml install
pip3 install --ignore-installed .
rm -rf build

cd /msgspec

MSGSPEC_DEBUG=1 CC=afl-clang-fast CFLAGS="-fsanitize=address -Wl,-rpath=/usr/lib/clang/14.0.6/lib/linux/" LDFLAGS="/usr/local/lib/afl/afl-compiler-rt.o /usr/lib/clang/14.0.6/lib/linux/libclang_rt.asan-x86_64.so" LDSHARED="clang -shared" pip3 install --ignore-installed .
rm -rf build

deactivate


# Prepare Atheris venv
source /atherisVenv/bin/activate

pip install atheris --ignore-installed
pip install coverage --ignore-installed
pip install testresources
pip install -U pip setuptools wheel

cd /tomli
pip3 install --ignore-installed .

cd /yaml-0.2.5
CC=clang CFLAGS="-g -fsanitize=fuzzer-no-link,address" ./configure
make install -j`nproc`

cd /PyYAML-5.3.1
CC=clang CFLAGS="-g -fsanitize=fuzzer-no-link,address" python3 setup.py --with-libyaml install
pip3 install --ignore-installed .

cd /msgspec
MSGSPEC_DEBUG=1 CC=clang CFLAGS="-g -fsanitize=fuzzer-no-link,address" LDSHARED="clang -shared" pip3 install --ignore-installed .

deactivate
