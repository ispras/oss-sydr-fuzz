#!/bin/bash -eu
# Copyright 2022 Google LLC
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

set -x

# In order to identify fuzztest test case "bazel query" is used to search
# the project. A search of the entire project is done with a default "...",
# however, some projects may fail to, or have very long processing time, if
# searching the entire project. Additionally, it may include fuzzers in
# dependencies, which should not be build as part of a given project.
# Tensorflow is an example project that will fail when the entire project is
# queried. FUZZTEST_TARGET_FOLDER makes it posible to specify the folder
# where fuzztest fuzzers should be search for. FUZZTEST_TARGET_FOLDER is passed
# to "bazel query" below.
if [[ ${FUZZTEST_TARGET_FOLDER:-"unset"} == "unset" ]];
then
  export TARGET_FOLDER="..."
else
  TARGET_FOLDER=${FUZZTEST_TARGET_FOLDER}
fi

BUILD_ARGS="--config=${CONFIG}"
if [[ ${FUZZTEST_EXTRA_ARGS:-"unset"} != "unset" ]];
then
  BUILD_ARGS="$BUILD_ARGS ${FUZZTEST_EXTRA_ARGS}"
fi

# Trigger setup_configs rule of fuzztest as it generates the necessary
# configuration file based on OSS-Fuzz environment variables.
/setup_configs.sh >> ./.bazelrc

# Bazel target names of the fuzz binaries.
FUZZ_TEST_BINARIES=$(bazel query "kind(\"cc_test\", rdeps(${TARGET_FOLDER}, @com_google_fuzztest//fuzztest:fuzztest_gtest_main))")

# Bazel output paths of the fuzz binaries.
FUZZ_TEST_BINARIES_OUT_PATHS=$(bazel cquery "kind(\"cc_test\", rdeps(${TARGET_FOLDER}, @com_google_fuzztest//fuzztest:fuzztest_gtest_main))" --output=files)

# Build the project and fuzz binaries
# Expose `FUZZTEST_EXTRA_TARGETS` environment variable, in the event a project
# includes non-FuzzTest fuzzers then this can be used to compile these in the
# same `bazel build` command as when building the FuzzTest fuzzers.
# This is to avoid having to call `bazel build` twice.
bazel build $BUILD_ARGS -- ${FUZZ_TEST_BINARIES[*]} ${FUZZTEST_EXTRA_TARGETS:-}

# Iterate the fuzz binaries and list each fuzz entrypoint in the binary. For
# each entrypoint create a wrapper script that calls into the binaries the
# given entrypoint as argument.
# The scripts will be named:
# {binary_name}@{fuzztest_entrypoint}
for fuzz_main_file in $FUZZ_TEST_BINARIES_OUT_PATHS; do
  cp ${fuzz_main_file} $OUT/
  if [[ $CONFIG = "libfuzzer" ]]
  then
    FUZZ_TESTS=$($fuzz_main_file --list_fuzz_tests)
    fuzz_basename=$(basename $fuzz_main_file)
    for fuzz_entrypoint in $FUZZ_TESTS; do
      TARGET_FUZZER="$OUT/${fuzz_basename}_run"
      $CC $CFLAGS \
          -DFUZZER=\"$OUT/$fuzz_basename\" \
          -DTARGET=\"$fuzz_entrypoint\" \
          -o $TARGET_FUZZER \
	  /run_fuzzer.c
    done
  fi
done
