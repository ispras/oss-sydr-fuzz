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

cd /pytorch_fuzz/
# Build torch with sans
MAX_JOBS=$(nproc) USE_FBGEMM=0 BUILD_BINARY=1 CC=clang CXX=clang++ USE_STATIC_MKL=1 \
	USE_DISTRIBUTED=0 USE_MPI=0 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=0 BUILD_TEST=0 \
	BUILD_SHARED_LIBS=OFF USE_OPENMP=0 USE_MKLDNN=0 \
	CXXFLAGS='-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero' \
	CFLAGS='-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero' \
	python3 setup.py build

cd build

# Build load_fuzz target
clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/pytorch_fuzz/torch/include \
	/load_fuzz.cc -c \
	-o ./load_fuzz.o

# Link load_fuzz target
clang++ -g -O2 -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./load_fuzz.o \
	lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	lib/libbreakpad.a \
	lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	lib/libqnnpack.a \
	lib/libpytorch_qnnpack.a \
	lib/libnnpack.a \
	lib/libXNNPACK.a \
	lib/libpthreadpool.a \
	lib/libcpuinfo.a \
	lib/libclog.a \
	lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	lib/libkineto.a \
	sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a  \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /load_fuzz

# Build mobile_fuzz target
clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/pytorch_fuzz/torch/include \
	/mobile_fuzz.cc -c \
	-o ./mobile_fuzz.o

# Link mobile_fuzz target
clang++ -g -O2 -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./mobile_fuzz.o \
	lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	lib/libbreakpad.a \
	lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	lib/libqnnpack.a \
	lib/libpytorch_qnnpack.a \
	lib/libnnpack.a \
	lib/libXNNPACK.a \
	lib/libpthreadpool.a \
	lib/libcpuinfo.a \
	lib/libclog.a \
	lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	lib/libkineto.a \
	sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /mobile_fuzz

# Build dump_fuzz target
clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/pytorch_fuzz/torch/include \
	/dump_fuzz.cc -c \
	-o ./dump_fuzz.o

# Link dump_fuzz target
clang++ -g -O2 -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./dump_fuzz.o \
	lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	lib/libbreakpad.a \
	lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	lib/libqnnpack.a \
	lib/libpytorch_qnnpack.a \
	lib/libnnpack.a \
	lib/libXNNPACK.a \
	lib/libpthreadpool.a \
	lib/libcpuinfo.a \
	lib/libclog.a \
	lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	lib/libkineto.a \
	sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /dump_fuzz
