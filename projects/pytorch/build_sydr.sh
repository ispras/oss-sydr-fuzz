# Copyright 2022 ISP RAS
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

#!/bin/bash -eu

cd /pytorch_sydr
# Build torch without sans
MAX_JOBS=$(nproc) USE_FBGEMM=0 BUILD_BINARY=1 CC=clang CXX=clang++ USE_STATIC_MKL=1 USE_DISTRIBUTED=0 USE_MPI=0 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=0 BUILD_TEST=0 BUILD_SHARED_LIBS=OFF USE_OPENMP=0 USE_MKLDNN=0 CXXFLAGS='-g' CFLAGS='-g' python3 setup.py build

cd build

# Build load_sydr target
clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 -DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 -DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 -DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch -DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO -DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK -DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 -I/pytorch_sydr/torch/include /load_sydr.cc -c -o ./load_sydr.o

# Link load_sydr target
clang++ -g -O2 -std=gnu++14 -DNDEBUG ./load_sydr.o lib/libtorch.a \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive  \
lib/libbreakpad.a  \
lib/libbreakpad_common.a  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive  \
lib/libqnnpack.a  \
lib/libpytorch_qnnpack.a  \
lib/libnnpack.a  \
lib/libXNNPACK.a  \
lib/libpthreadpool.a  \
lib/libcpuinfo.a  \
lib/libclog.a \
lib/libfoxi_loader.a  \
-lrt -lm -ldl  \
lib/libkineto.a \
sleef/lib/libsleef.a  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libonnx.a" -Wl,--no-whole-archive  \
lib/libonnx_proto.a  \
lib/libprotobuf.a  \
-pthread \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx.a" -Wl,--no-whole-archive  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx2.a" -Wl,--no-whole-archive  \
lib/libc10.a  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx512.a" -Wl,--no-whole-archive \
-o /load_sydr

# Build mobile_sydr target
clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 -DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 -DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 -DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch -DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO -DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK -DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 -I/pytorch_sydr/torch/include /mobile_sydr.cc -c -o ./mobile_sydr.o

# Link mobile_sydr target
clang++ -g -O2 -std=gnu++14 -DNDEBUG ./mobile_sydr.o lib/libtorch.a \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive  \
lib/libbreakpad.a  \
lib/libbreakpad_common.a  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive  \
lib/libqnnpack.a  \
lib/libpytorch_qnnpack.a  \
lib/libnnpack.a  \
lib/libXNNPACK.a  \
lib/libpthreadpool.a  \
lib/libcpuinfo.a  \
lib/libclog.a \
lib/libfoxi_loader.a  \
-lrt -lm -ldl  \
lib/libkineto.a \
sleef/lib/libsleef.a  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libonnx.a" -Wl,--no-whole-archive  \
lib/libonnx_proto.a  \
lib/libprotobuf.a  \
-pthread \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx.a" -Wl,--no-whole-archive  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx2.a" -Wl,--no-whole-archive  \
lib/libc10.a  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx512.a" -Wl,--no-whole-archive \
-o /mobile_sydr

# Build dump_sydr target
clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 -DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 -DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 -DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch -DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO -DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK -DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 -I/pytorch_sydr/torch/include /dump_sydr.cc -c -o ./dump_sydr.o

# Link dump_sydr target
clang++ -g -O2 -std=gnu++14 -DNDEBUG ./dump_sydr.o lib/libtorch.a \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive  \
lib/libbreakpad.a  \
lib/libbreakpad_common.a  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive  \
lib/libqnnpack.a  \
lib/libpytorch_qnnpack.a  \
lib/libnnpack.a  \
lib/libXNNPACK.a  \
lib/libpthreadpool.a  \
lib/libcpuinfo.a  \
lib/libclog.a \
lib/libfoxi_loader.a  \
-lrt -lm -ldl  \
lib/libkineto.a \
sleef/lib/libsleef.a  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libonnx.a" -Wl,--no-whole-archive  \
lib/libonnx_proto.a  \
lib/libprotobuf.a  \
-pthread \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx.a" -Wl,--no-whole-archive  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx2.a" -Wl,--no-whole-archive  \
lib/libc10.a  \
-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx512.a" -Wl,--no-whole-archive \
-o /dump_sydr
