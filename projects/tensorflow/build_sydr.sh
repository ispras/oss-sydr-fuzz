#!/bin/bash -eu
# Copyright 2018 Google Inc.
# Modifications copyright (C) 2021 ISP RAS
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

# Sydr

#export JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
#export PATH=$JAVA_HOME/bin:$PATH

export LIB_FUZZING_ENGINE="/main.o"
clang -g -c /main.c -o $LIB_FUZZING_ENGINE
export CC=clang
export CXX=clang++
export CFLAGS="-g"
export CXXFLAGS="-g"
SANITIZERS=""

# Force Python3, run configure.py to pick the right build config
PYTHON=python3
yes "" | ${PYTHON} configure.py

# Since Bazel passes flags to compilers via `--copt`, `--conlyopt` and
# `--cxxopt`, we need to move all flags from `$CFLAGS` and `$CXXFLAGS` to these.
# We don't use `--copt` as warnings issued by C compilers when encountering a
# C++-only option results in errors during build.
#
# Note: Make sure that by this line `$CFLAGS` and `$CXXFLAGS` are properly set
# up as further changes to them won't be visible to Bazel.
#
# Note: for builds using the undefined behavior sanitizer we need to link
# `clang_rt` ubsan library. Since Bazel uses `clang` for linking instead of
# `clang++`, we need to add the additional `--linkopt` flag.
# See issue: https://github.com/bazelbuild/bazel/issues/8777

mkdir /sydr

declare EXTRA_FLAGS="\
$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
    echo "--cxxopt=${f}" "--linkopt=${f}"
done
)"

sed -i -e 's/linkstatic/linkopts = \["\/main.o -ldl"\],\nlinkstatic/' tensorflow/security/fuzzing/tf_fuzzing.bzl
# Determine all fuzz targets. To control what gets fuzzed with OSSFuzz, all
# supported fuzzers are in `//tensorflow/security/fuzzing`.
# Ignore fuzzers tagged with `no_oss` in opensource.
declare FUZZERS=$(bazel query 'kind(cc_.*, tests(//tensorflow/security/fuzzing/...)) - attr(tags, no_oss, kind(cc_.*, tests(//tensorflow/security/fuzzing/...)))' | grep -v checkpoint_reader_fuzz)
# checkpoint_reader_fuzz seems out of date with the API

# Build the fuzzer targets.
# Pass in `--config=libc++` to link against libc++.
# Pass in `--verbose_failures` so it is easy to debug compile crashes.
# Pass in `--strip=never` to ensure coverage support.
# Since we have `assert` in fuzzers, make sure `NDEBUG` is not defined
bazel build \
  --jobs=$(nproc) \
  --config=libc++ \
  --subcommands \
  ${EXTRA_FLAGS} \
  --verbose_failures \
  --strip=never \
  --copt='-UNDEBUG' \
  -- ${FUZZERS}

# The fuzzers built above are in the `bazel-bin/` symlink. But they need to be
# in `$OUT`, so move them accordingly.
for bazel_target in ${FUZZERS}; do
  colon_index=$(expr index "${bazel_target}" ":")
  fuzz_name="${bazel_target:$colon_index}"
  bazel_location="bazel-bin/${bazel_target/:/\/}"
  cp ${bazel_location} /sydr/$fuzz_name
done

rm -f bazel-*
rm -rf /root/.cache/bazel/_bazel_root

echo "  write_to_bazelrc('import %workspace%/tools/bazel.rc')" >> configure.py
yes "" | ./configure

declare EXTRA_FLAGS="\
$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
    echo "--cxxopt=${f}" "--linkopt=${f}"
done
)"

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
        ]
    )
END

cat >> tensorflow/core/kernels/fuzzing/BUILD << END

load("//tensorflow/core/kernels/fuzzing:tf_ops_fuzz_target_lib.bzl", "cc_tf")

END

for fuzzer in ${FUZZERS}; do
    echo cc_tf\(\"${fuzzer}\"\) >> tensorflow/core/kernels/fuzzing/BUILD
done

bazel build \
  -k \
  --jobs=$(nproc) \
  --config=monolithic \
  --dynamic_mode=off \
  --subcommands \
  ${EXTRA_FLAGS} \
  --verbose_failures \
  --strip=never \
  --copt='-UNDEBUG' \
  --define=framework_shared_object=false \
  -- //tensorflow/core/kernels/fuzzing:all || true

for fuzzer in ${FUZZERS}; do
  fuzz_path="bazel-bin/tensorflow/core/kernels/fuzzing/${fuzzer}_fuzz"
  cp ${fuzz_path} /sydr/${fuzzer}_fuzz
done

# Finally, make sure we don't accidentally run with stuff from the bazel cache.
rm -f bazel-*
rm -rf /root/.cache/bazel/_bazel_root
