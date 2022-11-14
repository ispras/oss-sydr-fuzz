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
MAX_JOBS=$(nproc) USE_FBGEMM=0 BUILD_BINARY=1 CC=clang CXX=clang++ USE_STATIC_MKL=1 \
	USE_DISTRIBUTED=0 USE_MPI=0 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=0 BUILD_TEST=0 \
	BUILD_SHARED_LIBS=OFF USE_OPENMP=0 USE_MKLDNN=0 \
	CXXFLAGS='-g' \
	CFLAGS='-g' \
	python3 setup.py build

# Patch PyTorch headers to build torchvision with clang
sed -i '1 i\#define ORDERED_DICT' /pytorch_sydr/torch/include/torch/csrc/api/include/torch/ordered_dict.h
sed -i '1 i\#ifndef ORDERED_DICT' /pytorch_sydr/torch/include/torch/csrc/api/include/torch/ordered_dict.h
echo "#endif" >> /pytorch_sydr/torch/include/torch/csrc/api/include/torch/ordered_dict.h

sed -i '1 i\#define ORDERED_DICT' /pytorch_sydr/torch/csrc/api/include/torch/ordered_dict.h
sed -i '1 i\#ifndef ORDERED_DICT' /pytorch_sydr/torch/csrc/api/include/torch/ordered_dict.h
echo "#endif" >> /pytorch_sydr/torch/csrc/api/include/torch/ordered_dict.h

sed -i '1 i\#define TYPES' /pytorch_sydr/torch/include/torch/csrc/api/include/torch/types.h
sed -i '1 i\#ifndef TYPES' /pytorch_sydr/torch/include/torch/csrc/api/include/torch/types.h
echo "#endif" >> /pytorch_sydr/torch/include/torch/csrc/api/include/torch/types.h

sed -i '1 i\#define TYPES' /pytorch_sydr/torch/csrc/api/include/torch/types.h
sed -i '1 i\#ifndef TYPES' /pytorch_sydr/torch/csrc/api/include/torch/types.h
echo "#endif" >> /pytorch_sydr/torch/csrc/api/include/torch/types.h

# Build libpng
cd /
wget http://download.sourceforge.net/libpng/libpng-1.6.37.tar.gz
tar -xvzf libpng-1.6.37.tar.gz
mv /libpng-1.6.37/ /libpng-1.6.37-sydr/
cd /libpng-1.6.37-sydr/
CC=clang \
	CFLAGS="-g" \
	./configure
make -j$(nproc)

# Build libjpeg-turbo
cd /
wget https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/2.1.3.tar.gz
tar -xvzf 2.1.3.tar.gz
mv /libjpeg-turbo-2.1.3/ /libjpeg-turbo-2.1.3-sydr/
cd /libjpeg-turbo-2.1.3-sydr/
cmake -G"Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_STATIC=1 \
	-DENABLE_SHARED=0 -DWITH_JPEG8=1 \
	-DCMAKE_C_FLAGS="-g" \
	-S . -B build/
cd build/
make -j$(nproc)

cd /
git clone https://github.com/madler/zlib.git zlib_sydr
cd zlib_sydr
git checkout v1.2.13
CC=clang CXX=clang++ \
	CFLAGS="-g" CXXFLAGS="-g" \
	./configure
make -j$(nproc)

# Build torchvision
cd /vision_sydr/
Torch_DIR=/pytorch_sydr/ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
	-DCMAKE_C_FLAGS="-g" \
	-DCMAKE_CXX_FLAGS="-g -I/pytorch_sydr/torch/csrc/api/include -I/pytorch_sydr/torch/include -I/libjpeg-turbo-2.1.3-sydr/" \
	-S . -B build/

cd build/

cmake --build . -j$(nproc)

# Build main.c with LLVMFuzzerTestOneInput

clang++ -c /main.cc -g -O2 -o ./main.o

# Build decode_jpeg_sydr target

clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-I/libjpeg-turbo-2.1.3-sydr/ -I/pytorch_sydr/torch/include \
	/decode_jpeg_fuzz.cc \
	-I/pytorch_sydr/torch/csrc/api/include -I/vision_sydr/torchvision/csrc/io/image \
	-I/vision_sydr/torchvision/csrc/io/image/cpu -c \
	-o ./decode_jpeg_sydr.o

# Link decode_jpeg_sydr target

clang++ -g -O2 -std=gnu++14 -DNDEBUG \
	./decode_jpeg_sydr.o \
	/pytorch_sydr/torch/lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive \
	./main.o \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_sydr/build/libtorchvision.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_sydr/torch/lib/libqnnpack.a /pytorch_sydr/torch/lib/libpytorch_qnnpack.a \
	/pytorch_sydr/torch/lib/libnnpack.a /pytorch_sydr/torch/lib/libXNNPACK.a \
	/pytorch_sydr/torch/lib/libpthreadpool.a /pytorch_sydr/torch/lib/libcpuinfo.a \
	/pytorch_sydr/torch/lib/libclog.a /pytorch_sydr/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_sydr/torch/lib/libkineto.a /pytorch_sydr/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_sydr/build/lib/libonnx_proto.a /pytorch_sydr/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_sydr/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libjpeg-turbo-2.1.3-sydr/build/libturbojpeg.a \
	-o /decode_jpeg_sydr

# Build decode_png_sydr target

clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-I/pytorch_sydr/torch/include \
	/decode_png_fuzz.cc -I/pytorch_sydr/torch/csrc/api/include \
	-I/vision_sydr/torchvision/csrc/io/image -I/vision_sydr/torchvision/csrc/io/image/cpu \
	-I/libpng-1.6.37-sydr/ -c \
	-o ./decode_png_sydr.o

# Link decode_png_sydr target

clang++ -g -O2 -std=gnu++14 -DNDEBUG \
	./decode_png_sydr.o \
	/pytorch_sydr/torch/lib/libtorch.a \
	./main.o \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_sydr/build/libtorchvision.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_sydr/torch/lib/libqnnpack.a /pytorch_sydr/torch/lib/libpytorch_qnnpack.a \
	/pytorch_sydr/torch/lib/libnnpack.a /pytorch_sydr/torch/lib/libXNNPACK.a \
	/pytorch_sydr/torch/lib/libpthreadpool.a /pytorch_sydr/torch/lib/libcpuinfo.a \
	/pytorch_sydr/torch/lib/libclog.a /pytorch_sydr/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_sydr/torch/lib/libkineto.a /pytorch_sydr/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_sydr/build/lib/libonnx_proto.a /pytorch_sydr/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_sydr/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libpng-1.6.37-sydr/./.libs/libpng16.a \
	/zlib_sydr/libz.a \
	-o /decode_png_sydr

# Build encode_jpeg_sydr target

clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-I/libjpeg-turbo-2.1.3-sydr/ -I/pytorch_sydr/torch/include \
	/encode_jpeg_fuzz.cc \
	-I/pytorch_sydr/torch/csrc/api/include -I/vision_sydr/torchvision/csrc/io/image \
	-I/vision_sydr/torchvision/csrc/io/image/cpu -c \
	-o ./encode_jpeg_sydr.o

# Link decode_jpeg_sydr target

clang++ -g -O2 -std=gnu++14 -DNDEBUG \
	./encode_jpeg_sydr.o \
	/pytorch_sydr/torch/lib/libtorch.a \
	./main.o \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_sydr/build/libtorchvision.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_sydr/torch/lib/libqnnpack.a /pytorch_sydr/torch/lib/libpytorch_qnnpack.a \
	/pytorch_sydr/torch/lib/libnnpack.a /pytorch_sydr/torch/lib/libXNNPACK.a \
	/pytorch_sydr/torch/lib/libpthreadpool.a /pytorch_sydr/torch/lib/libcpuinfo.a \
	/pytorch_sydr/torch/lib/libclog.a /pytorch_sydr/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_sydr/torch/lib/libkineto.a /pytorch_sydr/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_sydr/build/lib/libonnx_proto.a /pytorch_sydr/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_sydr/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive /libjpeg-turbo-2.1.3-sydr/build/libturbojpeg.a \
	-o /encode_jpeg_sydr

# Build encode_png_sydr target

clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-I/pytorch_sydr/torch/include \
	/encode_png_fuzz.cc \
	-I/pytorch_sydr/torch/csrc/api/include -I/vision_sydr/torchvision/csrc/io/image \
	-I/vision_sydr/torchvision/csrc/io/image/cpu -I/libpng-1.6.37-sydr/ -c \
	-o ./encode_png_sydr.o

# Link encode_png_sydr target

clang++ -g -O2 -std=gnu++14 -DNDEBUG \
	./encode_png_sydr.o \
	/pytorch_sydr/torch/lib/libtorch.a \
	./main.o \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_sydr/build/libtorchvision.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_sydr/torch/lib/libqnnpack.a /pytorch_sydr/torch/lib/libpytorch_qnnpack.a \
	/pytorch_sydr/torch/lib/libnnpack.a /pytorch_sydr/torch/lib/libXNNPACK.a \
	/pytorch_sydr/torch/lib/libpthreadpool.a /pytorch_sydr/torch/lib/libcpuinfo.a \
	/pytorch_sydr/torch/lib/libclog.a /pytorch_sydr/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_sydr/torch/lib/libkineto.a /pytorch_sydr/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_sydr/build/lib/libonnx_proto.a /pytorch_sydr/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_sydr/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_sydr/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libpng-1.6.37-sydr/./.libs/libpng16.a \
	/zlib_sydr/libz.a \
	-o /encode_png_sydr
