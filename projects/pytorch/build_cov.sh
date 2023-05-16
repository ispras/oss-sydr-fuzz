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

cd /pytorch_cov
# Build torch for cov
MAX_JOBS=$(nproc) USE_ITT=0 USE_FBGEMM=0 BUILD_BINARY=1 CC=clang CXX=clang++ USE_STATIC_MKL=1 \
	USE_DISTRIBUTED=1 USE_MPI=1 TP_BUILD_LIBUV=1 USE_TENSORPIPE=1 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=0 BUILD_TEST=0 \
	BUILD_SHARED_LIBS=OFF USE_OPENMP=0 USE_MKLDNN=0 \
	CXXFLAGS='-fPIC -g -fprofile-instr-generate -fcoverage-mapping' \
	CFLAGS='-fPIC -g -fprofile-instr-generate -fcoverage-mapping' \
	python3 setup.py build

cd build

# Build class_parser_cov target
clang++ -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fprofile-instr-generate -fcoverage-mapping -I/pytorch_cov/torch/include \
	/class_parser_fuzz.cc /main-impl.cc -c

# Link class_parser_cov target
clang++ -g -O2 -fprofile-instr-generate -fcoverage-mapping -std=gnu++14 -DNDEBUG \
	./class_parser_fuzz.o ./main-impl.o \
	lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
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
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /class_parser_cov

# Build jit_differential_cov target
clang++ -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fprofile-instr-generate -fcoverage-mapping -I/pytorch_cov/torch/include \
	/jit_differential_fuzz.cc /main-impl.cc -c

# Link jit_differential_cov target
clang++ -g -O2 -fprofile-instr-generate -fcoverage-mapping -std=gnu++14 -DNDEBUG \
	./jit_differential_fuzz.o ./main-impl.o \
	lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
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
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /jit_differential_cov

# Build irparser_cov target
clang++ -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fprofile-instr-generate -fcoverage-mapping -I/pytorch_cov/torch/include \
	/irparser_fuzz.cc /main-impl.cc -c

# Link irparser_cov target
clang++ -g -O2 -fprofile-instr-generate -fcoverage-mapping -std=gnu++14 -DNDEBUG \
	./irparser_fuzz.o ./main-impl.o \
	lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
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
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /irparser_cov

# Build message_deserialize_cov target
clang++ -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK -DUSE_TENSORPIPE \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fprofile-instr-generate -fcoverage-mapping \
	-I/pytorch_cov/torch/include -I/pytorch_cov/torch/csrc/distributed \
	-I/pytorch_cov/torch/include/torch/csrc/api/include \
	/message_deserialize_fuzz.cc /main-impl.cc -c

# Link message_deserialize_cov target
clang++ -g -O2 -fprofile-instr-generate -fcoverage-mapping -std=gnu++14 -DNDEBUG \
	./message_deserialize_fuzz.o ./main-impl.o \
	lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
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
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /message_deserialize_cov

# Build load_cov target
clang++ -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fprofile-instr-generate -fcoverage-mapping -I/pytorch_cov/torch/include \
	/load_fuzz.cc /main-impl.cc -c

# Link load_cov target
clang++ -g -O2 -fprofile-instr-generate -fcoverage-mapping -std=gnu++14 -DNDEBUG \
	./load_fuzz.o ./main-impl.o \
	lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
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
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /load_cov

# Build mobile_cov target
clang++ -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1\
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fprofile-instr-generate -fcoverage-mapping -I/pytorch_cov/torch/include \
	/mobile_fuzz.cc /main-impl.cc -c

# Link mobile_cov target
clang++ -g -O2 -fprofile-instr-generate -fcoverage-mapping -std=gnu++14 -DNDEBUG \
	./mobile_fuzz.o ./main-impl.o lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
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
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /mobile_cov

# Build dump_cov target
clang++ -DUSE_ITT=0 -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG \
	-DUSE_KINETO -DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fprofile-instr-generate -fcoverage-mapping -I/pytorch_cov/torch/include \
	/dump_fuzz.cc /main-impl.cc -c

# Link dump_cov target
clang++ -g -O2 -fprofile-instr-generate -fcoverage-mapping -std=gnu++14 -DNDEBUG \
	./dump_fuzz.o ./main-impl.o \
	lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
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
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libonnx.a" -Wl,--no-whole-archive \
	lib/libonnx_proto.a \
	lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_cov/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	-o /dump_cov
