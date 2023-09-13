#!/bin/bash -x
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

flags_to_bazel_flags()
{
  bazel_flag=$1
  flag=$2

  # When we have something along -fno-sanitize-recover=bool,array,...,.. we
  # need to split them out and write each assignment without use of commas. Otherwise
  # the per_file_copt option splits the comma string with spaces, which causes the
  # build command to be erroneous.
  if [[ $flag == *","* && $flag == *"="* ]]; then
    # Split from first occurrence of equals.
    flag_split_over_equals=(${flag//=/ })
    lhs=${flag_split_over_equals[0]}
    comma_values=($(echo ${flag_split_over_equals[1]} | tr ',' " "))
    for val in "${comma_values[@]}"; do
      echo "build:${CONFIG} $bazel_flag=${lhs}=${val}"
    done
  else
    if [[ $flag != *"no-as-needed"* ]]; then
      # Flags captured here include -fsanitize=fuzzer-no-link, -fsanitize=addresss.
      echo "build:${CONFIG} $bazel_flag=$flag"
    fi
  fi
}

echo "
build:${CONFIG} --copt=-DFUZZTEST_COMPATIBILITY_MODE
build:${CONFIG} --dynamic_mode=off
build:${CONFIG} --action_env=CC=${CC}
build:${CONFIG} --action_env=CXX=${CXX}
build:${CONFIG} --action_env=CLANG_COMPILER_PATH="${CC}"
build:${CONFIG} --repo_env=CC=${CC}
build:${CONFIG} --repo_env=BAZEL_COMPILER=${CC}
"

for flag in $CFLAGS; do
  echo "$(flags_to_bazel_flags "--conlyopt" $flag)"
  echo "$(flags_to_bazel_flags "--linkopt" $flag)"
done

for flag in $CXXFLAGS; do
  echo "$(flags_to_bazel_flags "--cxxopt" $flag)"
  echo "$(flags_to_bazel_flags "--linkopt" $flag)"
done

for f in ${SANITIZERS:-}; do
  if [[ ${f} = "undefined" ]]; then
    echo "build:${CONFIG} --linkopt=$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
  fi
done

echo "build:${CONFIG} --linkopt=${FUZZING_ENGINE}"
