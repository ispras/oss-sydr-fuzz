#!/bin/bash -x
# Copyright 2018 Google Inc.
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

if [[ $CONFIG = "libfuzzer" ]]
then
  export OUT="/fuzzer"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,bounds,integer,null"
  export CXXFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,bounds,integer,null"
  export SANITIZERS="address undefined"
  export LINKOPTS="-fsanitize=fuzzer,undefined,address,bounds,integer,null"
  export FUZZING_ENGINE="$(find $(llvm-config --libdir) -name libclang_rt.fuzzer_no_main-x86_64.a | head -1)"
fi

if [[ $CONFIG = "afl" ]]
then
  export OUT="/afl"
  export CC=afl-clang-fast
  export CXX=afl-clang-fast++
  export CFLAGS="-g -fsanitize=undefined,address,bounds,integer,null"
  export CXXFLAGS="-g -fsanitize=undefined,address,bounds,integer,null"
  export SANITIZERS="address undefined"
  export LINKOPTS="-fsanitize=undefined,address,bounds,integer,null"
  export FUZZING_ENGINE=/afl_driver.o
  $CC $CFLAGS -fPIC -o /afl_driver.o -c /afl_driver.cc
fi

if [[ $CONFIG = "sydr" ]]
then
  export OUT="/sydr"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g"
  export CXXFLAGS="-g"
  export LINKOPTS="-g"
  export FUZZING_ENGINE=/sydr_driver.o
  $CC $CFLAGS -fPIC -o /sydr_driver.o -c /sydr_driver.cc
fi

if [[ $CONFIG = "coverage" ]]
then
  export OUT="/cov"
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
  export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
  export LINKOPTS="-g -fprofile-instr-generate -fcoverage-mapping"
  export FUZZING_ENGINE=/sydr_driver.o
  $CC $CFLAGS -fPIC -o /sydr_driver.o -c /sydr_driver.cc
fi

mkdir $OUT
git apply --ignore-space-change --ignore-whitespace /fuzz_patch.patch

find tensorflow/ -name "BUILD" -exec sed -i 's/tf_cc_fuzz_test/tf_oss_fuzz_fuzztest/g' {} \;

# Overwrite compiler flags that break the oss-fuzz build
sed -i 's/build:linux --copt=\"-Wno-unknown-warning\"/# overwritten/g' ./.bazelrc
sed -i 's/build:linux --copt=\"-Wno-array-parameter\"/# overwritten/g' ./.bazelrc
sed -i 's/build:linux --copt=\"-Wno-stringop-overflow\"/# overwritten/g' ./.bazelrc

# Force Python3, run configure.py to pick the right build config
PYTHON=python3
yes "" | python3 configure.py

# Prepare flags for compiling fuzzers.
export FUZZTEST_EXTRA_ARGS="--jobs=$(nproc) --spawn_strategy=sandboxed --action_env=ASAN_OPTIONS=detect_leaks=0,detect_odr_violation=0 --define force_libcpp=enabled --verbose_failures --copt=-UNDEBUG --config=monolithic"

# Set fuzz targets
export FUZZTEST_TARGET_FOLDER="//tensorflow/security/fuzzing/...+//tensorflow/cc/saved_model/...+//tensorflow/cc/framework/fuzzing/...+//tensorflow/core/common_runtime/...+//tensorflow/core/framework/..."
export FUZZTEST_EXTRA_TARGETS="//tensorflow/core/kernels/fuzzing:all"

echo "  write_to_bazelrc('import %workspace%/tools/bazel.rc')" >> configure.py
yes "" | ./configure

declare FUZZERS=$(grep '^tf_ops_fuzz_target' tensorflow/core/kernels/fuzzing/BUILD | cut -d'"' -f2 | grep -v decode_base64)

cat >> tensorflow/core/kernels/fuzzing/tf_ops_fuzz_target_lib.bzl << END
def cc_tf(name):
    native.cc_test(
        name = name + "_fuzz",
        deps = [
            "//tensorflow/core/kernels/fuzzing:fuzz_session",
            "//tensorflow/core/kernels/fuzzing:" + name + "_fuzz_lib",
            "//tensorflow/cc:cc_ops",
            "//tensorflow/cc:scope",
            "//tensorflow/core:core_cpu",
        ],
        linkopts = ["$LINKOPTS"]
    )
END

cat >> tensorflow/core/kernels/fuzzing/BUILD << END
load("//tensorflow/core/kernels/fuzzing:tf_ops_fuzz_target_lib.bzl", "cc_tf")
END

for fuzzer in ${FUZZERS}; do
    echo cc_tf\(\"${fuzzer}\"\) >> tensorflow/core/kernels/fuzzing/BUILD
done

declare FUZZERS=$(bazel query 'kind(cc_.*, tests(//tensorflow/core/kernels/fuzzing/...))' | grep -v decode_base64)

/compile_fuzztests.sh

# Copy out all non-fuzztest fuzzers.
# The fuzzers built above are in the `bazel-bin/` symlink. But they need to be
# in `$OUT`, so move them accordingly.
for bazel_target in ${FUZZERS}; do
  colon_index=$(expr index "${bazel_target}" ":")
  fuzz_name="${bazel_target:$colon_index}"
  bazel_location="bazel-bin/${bazel_target/:/\/}"
  cp ${bazel_location} $OUT/$fuzz_name
done
