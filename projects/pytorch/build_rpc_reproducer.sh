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

cd /pytorch_sydr/build

# Build reproduce (nosan) binary
clang++ -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK -DUSE_TENSORPIPE\
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -DUSE_C10D_GLOO -g -O2 \
	-I/pytorch_sydr/torch/include -I/pytorch_sydr/torch/csrc/distributed \
	-I/pytorch_sydr/torch/include/torch/csrc/api/include \
	-I/pytorch_sydr/third_party/gloo/ \
	/rpc_reproducer.cc -c

# Link reproduce-nosan binary
clang++ -g -O2 -std=gnu++14 -DNDEBUG ./rpc_reproducer.o lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
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
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /rpc_reproducer_nosan

cd /pytorch_fuzz/build

# Build reproduce binary (with ASAN)
clang++ -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK -DUSE_TENSORPIPE\
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -DUSE_C10D_GLOO -g -O2 \
    -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/pytorch_sydr/torch/include -I/pytorch_sydr/torch/csrc/distributed \
	-I/pytorch_sydr/torch/include/torch/csrc/api/include \
	-I/pytorch_sydr/third_party/gloo/ \
	/rpc_reproducer.cc -c

# Link reproduce-asan binary
clang++ -g -O2 -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero -std=gnu++14 -DNDEBUG ./rpc_reproducer.o lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
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
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /rpc_reproducer_asan
