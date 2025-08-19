#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

export CC="clang" 
export CFLAGS="-fsanitize=fuzzer-no-link,address -g -shared-libasan" 
export CXX="clang++" 
export CXXFLAGS="-fsanitize=fuzzer-no-link,address -g -shared-libasan"

export LD_LIBRARY_PATH="$(dirname $(find $(llvm-config --libdir) -name libclang_rt.asan-x86_64.so | head -1))"
export TF_PYTHON_VERSION=3.9

declare EXTRA_FLAGS="\
$(
for f in ${CFLAGS}; do
    echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
    echo "--cxxopt=${f}" "--linkopt=${f}"
done
)"

sed -i -e 's/$(location @nasm\/\/:nasm) -f elf64/ASAN_OPTIONS=detect_leaks=0 $(location @nasm\/\/:nasm) -f elf64/' third_party/jpeg/jpeg.BUILD

python3 -m pip install numpy wheel packaging requests opt_einsum toml
python3 -m pip install keras_preprocessing --no-deps

sed -i 's/build:linux --copt=\"-Wno-unknown-warning\"/# overwritten/g' ./.bazelrc
sed -i 's/build:linux --copt=\"-Wno-array-parameter\"/# overwritten/g' ./.bazelrc
sed -i 's/build:linux --copt=\"-Wno-stringop-overflow\"/# overwritten/g' ./.bazelrc

bazel clean --expunge
bazel build \
  --define=xnn_enable_avxvnniint8=false \
  --verbose_failures \
  --jobs=150 \
  --spawn_strategy=sandboxed \
  --strategy=CopyFile=sandboxed,standalone \
  --strip=never \
  --copt="-DADDRESS_SANITIZER" \
  --action_env="ASAN_OPTIONS=detect_leaks=0,detect_odr_violation=0" \
  --action_env="LD_PRELOAD=$(find $(llvm-config --libdir) -name libclang_rt.asan-x86_64.so | head -1)" \
  ${EXTRA_FLAGS} \
  --remote_timeout=3600 --action_env=CppCompileTimeout=3600 \
  -- //tensorflow/tools/pip_package:wheel

python3 -m pip install bazel-bin/tensorflow/tools/pip_package/wheel_house/tensorflow-2.20.0*.whl
