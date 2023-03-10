#!/bin/bash -x

# Script for generating fuzztest.bazelrc.

set -euf -o pipefail

echo "### DO NOT EDIT. Generated file.
#
# To regenerate, run the following from your project's workspace:
#
#  bazel run @com_google_fuzztest//bazel:setup_configs > fuzztest.bazelrc
#
# And don't forget to add the following to your project's .bazelrc:
#
#  try-import %workspace%/fuzztest.bazelrc
"

echo "
### Common options.
#
# Do not use directly.
# Link with Address Sanitizer (ASAN).
build:fuzztest-common --linkopt=-fsanitize=address
# Standard define for \"ifdef-ing\" any fuzz test specific code.
build:fuzztest-common --copt=-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
# In fuzz tests, we want to catch assertion violations even in optimized builds.
build:fuzztest-common --copt=-UNDEBUG
# Enable libc++ assertions.
# See https://libcxx.llvm.org/UsingLibcxx.html#enabling-the-safe-libc-mode
build:fuzztest-common --copt=-D_LIBCPP_ENABLE_ASSERTIONS=1
"

echo "
### FuzzTest build configuration.
#
# Use with: --config=fuzztest
build:fuzztest --config=fuzztest-common
# Link statically.
build:fuzztest --dynamic_mode=off
# We rely on the following flag instead of the compiler provided
# __has_feature(address_sanitizer) to know that we have an ASAN build even in
# the uninstrumented runtime.
build:fuzztest --copt=-DADDRESS_SANITIZER
"

FUZZTEST_FILTER="fuzztest/.*"

echo "# We apply coverage tracking and ASAN instrumentation to everything but the
# FuzzTest framework itself (including GoogleTest and GoogleMock).
build:fuzztest --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@-fsanitize=address,-fsanitize-coverage=inline-8bit-counters,-fsanitize-coverage=trace-cmp
"

# Do not use the extra configurations below, unless you know what you're doing.

EXTRA_CONFIGS="${EXTRA_CONFIGS:-none}"

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

# libFuzzer
if [[ ${CONFIG} = "libfuzzer" ]]; then
#
#export CC=clang
#export CXX=clang++
#export CFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,integer,null,bounds"
#export CXXFLAGS="-g -fsanitize=fuzzer-no-link,undefined,address,integer,null,bounds"
#export SANITIZERS="address undefined"
export FUZZING_ENGINE="libfuzzer"

# AFL version in oss-fuzz does not support LLVMFuzzerRunDriver. It must be updated first.
#if [ "$FUZZING_ENGINE" = "afl" ]; then
#  echo "build:oss-fuzz --linkopt=${LIB_FUZZING_ENGINE}"
#fi
fi # libFuzzer

## AFL++
#if [[ ${CONFIG} = "afl" ]]; then
#
#export CC=afl-clang-fast
#export CXX=afl-clang-fast++
#export CFLAGS="-g -fsanitize=address,undefined,integer,null,bounds"
#export CXXFLAGS="-g -fsanitize=address,undefined,integer,null,bounds"
#export SANITIZERS="address undefined"
#
#fi # AFL++
#
## Sydr
#if [[ ${CONFIG} = "sydr" ]]; then
#
#export CC=clang
#export CXX=clang++
#export CFLAGS="-g"
#export CXXFLAGS="-g"
#
#fi # Sydr
#
## Coverage
#if [[ ${CONFIG} = "coverage" ]]; then
#
#export CC=clang
#export CXX=clang++
#export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
#export CXXFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
#
#fi # Coverage

echo "
build:${CONFIG} --copt=-DFUZZTEST_COMPATIBILITY_MODE
build:${CONFIG} --dynamic_mode=off
build:${CONFIG} --action_env=CC=${CC}
build:${CONFIG} --action_env=CXX=${CXX}
"

for flag in $CFLAGS; do
  echo "$(flags_to_bazel_flags "--conlyopt" $flag)"
  echo "$(flags_to_bazel_flags "--linkopt" $flag)"
done

for flag in $CXXFLAGS; do
  echo "$(flags_to_bazel_flags "--cxxopt" $flag)"
  echo "$(flags_to_bazel_flags "--linkopt" $flag)"
done

for f in ${SANITIZERS}; do
  if [[ ${f} = "undefined" ]]; then
    echo "build:${CONFIG} --linkopt=$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
  fi
done

if [[ "${FUZZING_ENGINE}" = "libfuzzer" ]]; then
  echo "build:${CONFIG} --linkopt=$(find $(llvm-config --libdir) -name libclang_rt.fuzzer_no_main-x86_64.a | head -1)"
fi
