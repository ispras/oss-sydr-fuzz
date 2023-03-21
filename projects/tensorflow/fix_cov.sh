#!/bin/bash -x

cd /tensorflow_cov

declare -r RSYNC_CMD="rsync -aLkR"
declare -r REMAP_PATH=/cov/proc/self/cwd/
mkdir -p ${REMAP_PATH}

# Synchronize the folder bazel-BAZEL_OUT_PROJECT.
declare -r RSYNC_FILTER_ARGS=("--include" "*.h" "--include" "*.cc" "--include" \
  "*.hpp" "--include" "*.cpp" "--include" "*.c" "--include" "*/" "--include" "*.inc" \
  "--include" "*.def" "--exclude" "*")

# Sync existing code.
${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" tensorflow/ ${REMAP_PATH}

# Sync generated proto files.
if [ -d "./bazel-out/k8-opt/bin/tensorflow/" ]
then
  ${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" ./bazel-out/k8-opt/bin/tensorflow/ ${REMAP_PATH}
fi
if [ -d "./bazel-out/k8-opt/bin/external" ]
then
  ${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" ./bazel-out/k8-opt/bin/external/ ${REMAP_PATH}
fi
if [ -d "./bazel-out/k8-opt/bin/third_party" ]
then
  ${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" ./bazel-out/k8-opt/bin/third_party/ ${REMAP_PATH}
fi

# Sync external dependencies. We don't need to include `bazel-tensorflow`.
# Also, remove `external/org_tensorflow` which is a copy of the entire source
# code that Bazel creates. Not removing this would cause `rsync` to expand a
# symlink that ends up pointing to itself!
pushd bazel-tensorflow_cov
[[ -e external/org_tensorflow ]] && unlink external/org_tensorflow
${RSYNC_CMD} external/ ${REMAP_PATH}
popd
