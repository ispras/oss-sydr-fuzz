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
# if [[ -z "${CFLAGS}" ]]; then
#     export ORIG_CFLAGS=""
# else
#     export ORIG_CFLAGS="$CFLAGS"
# fi

# if [[ -z "${CXXFLAGS}" ]]; then
#     export ORIG_CXXFLAGS=""
# else
#     export ORIG_CXXFLAGS="$CXXFLAGS"
# fi

export CC="clang" 
export CFLAGS="-fsanitize=address,fuzzer-no-link -g" 
export CXX="clang++" 
export CXXFLAGS="-fsanitize=address,fuzzer-no-link -g"
python3 -m pip install numpy
# export CFLAGS=$ORIG_CFLAGS
# export CXXFLAGS=$ORIG_CXXFLAGS
python3 -m pip install tf-nightly-cpu
export SRC=""
export OUT="tensorflow/tensorflow-out"

# Rename to avoid the following: https://github.com/tensorflow/tensorflow/issues/40182
mv $SRC/tensorflow/tensorflow $SRC/tensorflow/tensorflow_src

# Build fuzzers into $OUT. These could be detected in other ways.

for fuzzer in $(find $SRC -name '*_fuzz.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg

  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
LD_PRELOAD=ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \
\$this_dir/$fuzzer_package \$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done

mv $SRC/tensorflow/tensorflow_src $SRC/tensorflow/tensorflow
