#!/bin/bash
# Copyright 2023 ISP RAS
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

set -e

cd /pytorch

# Clean previous build
python3 setup.py clean

echo "Build directory clean"

# Build PyTorch libraries.
if [[ $TARGET == "fuzz" ]]
then
    CC=clang
    CXX=clang++
    CFLAGS="-fPIC -g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "afl" ]]
then
    CC=afl-clang-fast
    CXX=afl-clang-fast++
    # '-fno-sanitize=poniter-overflow' is a fix for clang-14 (https://github.com/llvm/llvm-project/issues/60442).
    CFLAGS="-fPIC -g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero -fno-sanitize=pointer-overflow"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "sydr" ]]
then
    CC=clang
    CXX=clang++
    CFLAGS="-fPIC -g"
    CXXFLAGS=$CFLAGS
elif [[ $TARGET == "cov" ]]
then
    CC=clang
    CXX=clang++
    CFLAGS="-fPIC -g -fprofile-instr-generate -fcoverage-mapping"
    CXXFLAGS=$CFLAGS
fi

CC=$CC CXX=$CXX CFLAGS=$CFLAGS CXXFLAGS=$CXXFLAGS MAX_JOBS=$(nproc) USE_ITT=0 USE_FBGEMM=0 BUILD_BINARY=1 USE_STATIC_MKL=1 \
    USE_DISTRIBUTED=1 USE_MPI=0 TP_BUILD_LIBUV=1 USE_TENSORPIPE=1 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=0 BUILD_TEST=0 \
    BUILD_SHARED_LIBS=OFF USE_OPENMP=0 USE_MKLDNN=0 \
    python3 setup.py build_clib

cd build

# Build targets.
if [[ $TARGET == "fuzz" || $TARGET == "afl" ]]
then
    TARGET_FLAGS="-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero"
else
    $CXX /main-impl.cc -c -o ./main-impl.o
fi
if [[ $TARGET == "cov" ]]
then
    TARGET_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
fi
MAIN=""
if [[ $TARGET == "sydr" || $TARGET == "cov" ]]
then
    MAIN="./main-impl.o"
fi

build_target(){
    target=$1
    extra=$2
    echo "=========== Build target ${target}_$TARGET ==========="
    # Build target
    $CXX -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
        -DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK -DTH_HAVE_THREAD \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -g -O2 -std=c++17 \
	$TARGET_FLAGS $extra -I/pytorch/torch/include \
	/$target.cc -c -o ./$target.o

    # Link target
    $CXX -g -O2 $TARGET_FLAGS -DNDEBUG ./$target.o $MAIN \
        lib/libtorch.a \
        -Wl,--whole-archive,"/pytorch/build/lib/libtorch.a" -Wl,--no-whole-archive \
        -Wl,--whole-archive,"/pytorch/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
        -Wl,--whole-archive,"/pytorch/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
        lib/libqnnpack.a \
        lib/libpytorch_qnnpack.a \
        lib/libnnpack.a \
        lib/libXNNPACK.a \
        lib/libpthreadpool.a \
        lib/libcpuinfo.a \
        lib/libclog.a \
        lib/libfoxi_loader.a \
        lib/libtensorpipe.a \
        /usr/lib/x86_64-linux-gnu/libuv.so.1.0.0 \
        lib/libgloo.a \
        -lrt -lm -ldl \
        lib/libkineto.a \
        sleef/lib/libsleef.a \
        -Wl,--whole-archive,"/pytorch/build/lib/libonnx.a" -Wl,--no-whole-archive \
        lib/libonnx_proto.a \
        lib/libprotobuf.a \
        -pthread \
        -Wl,--whole-archive,"/pytorch/build/lib/libCaffe2_perfkernels_avx.a" \
        -Wl,--no-whole-archive \
        -Wl,--whole-archive,"/pytorch/build/lib/libCaffe2_perfkernels_avx2.a" \
        -Wl,--no-whole-archive \
        lib/libc10.a  \
        -Wl,--whole-archive,"/pytorch/build/lib/libCaffe2_perfkernels_avx512.a" \
        -Wl,--no-whole-archive \
        -o /${target}_$TARGET
}

#targets=("class_parser" "jit_differential" "irparser" "message_deserialize" "load" "mobile" "dump")
targets=("class_parser" "jit_differential" "irparser" "message_deserialize" "load")
for fuzztarget in ${targets[@]}; do
    EXTRA_FLAGS=""
    if [[ $fuzztarget == "message_deserialize" ]]
    then
        EXTRA_FLAGS="-DUSE_TENSORPIPE -I/pytorch/torch/csrc/distributed -I/pytorch/torch/include/torch/csrc/api/include"
    fi
    build_target $fuzztarget "$EXTRA_FLAGS" &
done
wait

# Build rpc reproducer.
if [[ $TARGET == "sydr" ]]
then
    # Build rpc_reproducer_nosan
    EXTRA_FLAGS="-DUSE_TENSORPIPE -DUSE_C10D_GLOO -I/pytorch/torch/csrc/distributed -I/pytorch/torch/include/torch/csrc/api/include -I/pytorch/third_party/gloo"
    MAIN=""
    TARGET_ARGS=""
    build_target "rpc_reproducer" "$EXTRA_FLAGS"
    mv /rpc_reproducer_sydr /rpc_reproducer_nosan

    # Build rpc_reproducer_san
    TARGET_FLAGS="-fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero"
    build_target "rpc_reproducer" "$EXTRA_FLAGS"
    mv /rpc_reproducer_sydr /rpc_reproducer_asan
fi
