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

# ------------------- Build libFuzzer targets -------------------

cd /pytorch_fuzz/
# Build torch with sans
MAX_JOBS=$(nproc) USE_FBGEMM=0 BUILD_BINARY=1 CC=clang CXX=clang++ USE_STATIC_MKL=1 \
	USE_DISTRIBUTED=0 USE_MPI=0 BUILD_CAFFE2_OPS=0 BUILD_CAFFE2=0 BUILD_TEST=0 \
	BUILD_SHARED_LIBS=OFF USE_OPENMP=0 USE_MKLDNN=0 \
	CXXFLAGS='-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero' \
	CFLAGS='-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero' \
	python3 setup.py build

# Patch PyTorch headers to build torchvision with clang
sed -i '1 i\#define ORDERED_DICT' /pytorch_fuzz/torch/include/torch/csrc/api/include/torch/ordered_dict.h
sed -i '1 i\#ifndef ORDERED_DICT' /pytorch_fuzz/torch/include/torch/csrc/api/include/torch/ordered_dict.h
echo "#endif" >> /pytorch_fuzz/torch/include/torch/csrc/api/include/torch/ordered_dict.h

sed -i '1 i\#define ORDERED_DICT' /pytorch_fuzz/torch/csrc/api/include/torch/ordered_dict.h
sed -i '1 i\#ifndef ORDERED_DICT' /pytorch_fuzz/torch/csrc/api/include/torch/ordered_dict.h
echo "#endif" >> /pytorch_fuzz/torch/csrc/api/include/torch/ordered_dict.h


sed -i '1 i\#define TYPES' /pytorch_fuzz/torch/include/torch/csrc/api/include/torch/types.h
sed -i '1 i\#ifndef TYPES' /pytorch_fuzz/torch/include/torch/csrc/api/include/torch/types.h
echo "#endif" >> /pytorch_fuzz/torch/include/torch/csrc/api/include/torch/types.h

sed -i '1 i\#define TYPES' /pytorch_fuzz/torch/csrc/api/include/torch/types.h
sed -i '1 i\#ifndef TYPES' /pytorch_fuzz/torch/csrc/api/include/torch/types.h
echo "#endif" >> /pytorch_fuzz/torch/csrc/api/include/torch/types.h

# Build libpng
cd /
wget http://download.sourceforge.net/libpng/libpng-1.6.37.tar.gz
tar -xvzf libpng-1.6.37.tar.gz
mv /libpng-1.6.37/ /libpng-1.6.37-fuzz/
cd /libpng-1.6.37-fuzz/
CC=clang \
	CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
	./configure
make -j$(nproc)

# Build libjpeg-turbo
cd /
wget https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/2.1.3.tar.gz
tar -xvzf 2.1.3.tar.gz
mv /libjpeg-turbo-2.1.3/ /libjpeg-turbo-2.1.3-fuzz/
cd /libjpeg-turbo-2.1.3-fuzz/
cmake -G"Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_STATIC=1 \
	-DENABLE_SHARED=0 -DWITH_JPEG8=1 \
	-DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
	-S . -B build/
cd build/
make -j$(nproc)

# Build zlib
cd /
wget https://zlib.net/zlib1212.zip
unzip zlib1212.zip
mv zlib-1.2.12/ zlib-1.2.12-fuzz/
cd zlib-1.2.12-fuzz/
CC=clang CXX=clang++ \
	CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
	CXXFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
	./configure
make -j$(nproc)

# Build torchvision
cd /vision_fuzz/
Torch_DIR=/pytorch_fuzz/ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
	-DCMAKE_C_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero" \
	-DCMAKE_CXX_FLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,integer,undefined,null,float-divide-by-zero -I/pytorch_fuzz/torch/csrc/api/include -I/pytorch_fuzz/torch/include -I/libjpeg-turbo-2.1.3-fuzz/" \
	-S . -B build/

cd build/

cmake --build . -j$(nproc)

# Build decode_jpeg_fuzz target

clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/libjpeg-turbo-2.1.3-fuzz/ -I/pytorch_fuzz/torch/include \
	/decode_jpeg_fuzz.cc \
	-I/pytorch_fuzz/torch/csrc/api/include -I/vision_fuzz/torchvision/csrc/io/image \
	-I/vision_fuzz/torchvision/csrc/io/image/cpu -c \
	-o ./decode_jpeg_fuzz.o

# Link decode_jpeg_fuzz target

clang++ -g -O2 \
	-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero -std=gnu++14 \
	-DNDEBUG \
	./decode_jpeg_fuzz.o \
	/pytorch_fuzz/torch/lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_fuzz/build/libtorchvision.a /pytorch_fuzz/build/lib/libbreakpad.a \
	/pytorch_fuzz/build/lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libqnnpack.a /pytorch_fuzz/torch/lib/libpytorch_qnnpack.a \
	/pytorch_fuzz/torch/lib/libnnpack.a /pytorch_fuzz/torch/lib/libXNNPACK.a \
	/pytorch_fuzz/torch/lib/libpthreadpool.a /pytorch_fuzz/torch/lib/libcpuinfo.a \
	/pytorch_fuzz/torch/lib/libclog.a /pytorch_fuzz/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_fuzz/torch/lib/libkineto.a /pytorch_fuzz/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/build/lib/libonnx_proto.a /pytorch_fuzz/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libjpeg-turbo-2.1.3-fuzz/build/libturbojpeg.a \
	-o /decode_jpeg_fuzz

# Build decode_png_fuzz target

clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/pytorch_fuzz/torch/include \
	/decode_png_fuzz.cc -I/pytorch_fuzz/torch/csrc/api/include \
	-I/vision_fuzz/torchvision/csrc/io/image -I/vision_fuzz/torchvision/csrc/io/image/cpu \
	-I/libpng-1.6.37-fuzz/ -c \
	-o ./decode_png_fuzz.o

# Link decode_png_fuzz target

clang++ -g -O2 -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./decode_png_fuzz.o \
	/pytorch_fuzz/torch/lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_fuzz/build/libtorchvision.a /pytorch_fuzz/build/lib/libbreakpad.a \
	/pytorch_fuzz/build/lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libqnnpack.a /pytorch_fuzz/torch/lib/libpytorch_qnnpack.a \
	/pytorch_fuzz/torch/lib/libnnpack.a /pytorch_fuzz/torch/lib/libXNNPACK.a \
	/pytorch_fuzz/torch/lib/libpthreadpool.a /pytorch_fuzz/torch/lib/libcpuinfo.a \
	/pytorch_fuzz/torch/lib/libclog.a /pytorch_fuzz/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_fuzz/torch/lib/libkineto.a /pytorch_fuzz/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/build/lib/libonnx_proto.a /pytorch_fuzz/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libpng-1.6.37-fuzz/./.libs/libpng16.a \
	/zlib-1.2.12-fuzz/./libz.a \
	-o /decode_png_fuzz

# Build encode_jpeg_fuzz target

clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/libjpeg-turbo-2.1.3-fuzz/ -I/pytorch_fuzz/torch/include \
	/encode_jpeg_fuzz.cc \
	-I/pytorch_fuzz/torch/csrc/api/include -I/vision_fuzz/torchvision/csrc/io/image \
	-I/vision_fuzz/torchvision/csrc/io/image/cpu -c \
	-o ./encode_jpeg_fuzz.o

# Link encode_jpeg_fuzz target

clang++ -g -O2 -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./encode_jpeg_fuzz.o \
	/pytorch_fuzz/torch/lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_fuzz/build/libtorchvision.a /pytorch_fuzz/build/lib/libbreakpad.a \
	/pytorch_fuzz/build/lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libqnnpack.a /pytorch_fuzz/torch/lib/libpytorch_qnnpack.a \
	/pytorch_fuzz/torch/lib/libnnpack.a /pytorch_fuzz/torch/lib/libXNNPACK.a \
	/pytorch_fuzz/torch/lib/libpthreadpool.a /pytorch_fuzz/torch/lib/libcpuinfo.a \
	/pytorch_fuzz/torch/lib/libclog.a /pytorch_fuzz/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_fuzz/torch/lib/libkineto.a /pytorch_fuzz/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/build/lib/libonnx_proto.a /pytorch_fuzz/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libjpeg-turbo-2.1.3-fuzz/build/libturbojpeg.a \
	-o /encode_jpeg_fuzz

# Build encode_png_fuzz target
 
clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/pytorch_fuzz/torch/include \
	/encode_png_fuzz.cc \
	-I/pytorch_fuzz/torch/csrc/api/include -I/vision_fuzz/torchvision/csrc/io/image \
	-I/vision_fuzz/torchvision/csrc/io/image/cpu -I/libpng-1.6.37-fuzz/ -c \
	-o ./encode_png_fuzz.o

# Link encode_png_fuzz target

clang++ -g -O2 -fsanitize=fuzzer,address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./encode_png_fuzz.o \
	/pytorch_fuzz/torch/lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_fuzz/build/libtorchvision.a /pytorch_fuzz/build/lib/libbreakpad.a \
	/pytorch_fuzz/build/lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libqnnpack.a /pytorch_fuzz/torch/lib/libpytorch_qnnpack.a \
	/pytorch_fuzz/torch/lib/libnnpack.a /pytorch_fuzz/torch/lib/libXNNPACK.a \
	/pytorch_fuzz/torch/lib/libpthreadpool.a /pytorch_fuzz/torch/lib/libcpuinfo.a \
	/pytorch_fuzz/torch/lib/libclog.a /pytorch_fuzz/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_fuzz/torch/lib/libkineto.a /pytorch_fuzz/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/build/lib/libonnx_proto.a /pytorch_fuzz/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libpng-1.6.37-fuzz/./.libs/libpng16.a \
	/zlib-1.2.12-fuzz/./libz.a \
	-o /encode_png_fuzz

# ------------------- Build AFL++ targets -------------------

# Build afl.o
afl-clang-fast++ -g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero -c \
	/afl.cc \
	-o /afl.o

# Build libpng AFL
cd /
tar -xvzf libpng-1.6.37.tar.gz
mv /libpng-1.6.37/ /libpng-1.6.37-fuzz-afl/
cd /libpng-1.6.37-fuzz-afl/
CC=afl-clang-fast \
	CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" \
	./configure
make -j$(nproc)

# Build libjpeg-turbo AFL
cd /
tar -xvzf 2.1.3.tar.gz
mv /libjpeg-turbo-2.1.3/ /libjpeg-turbo-2.1.3-fuzz-afl/
cd /libjpeg-turbo-2.1.3-fuzz-afl/
cmake -G"Unix Makefiles" \
	-DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_CXX_COMPILER=afl-clang-fast++ -DENABLE_STATIC=1 \
	-DENABLE_SHARED=0 -DWITH_JPEG8=1 \
	-DCMAKE_C_FLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" \
	-S . -B build/
cd build/
make -j$(nproc)

# Build zlib AFL
cd /
unzip zlib1212.zip
mv zlib-1.2.12/ zlib-1.2.12-fuzz-afl/
cd zlib-1.2.12-fuzz-afl/
CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" \
	CXXFLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" \
	./configure
make -j$(nproc)

# Build torchvision AFL
cd /vision_fuzz_afl/
Torch_DIR=/pytorch_fuzz/ cmake -DCMAKE_C_COMPILER=afl-clang-fast \
	-DCMAKE_CXX_COMPILER=afl-clang-fast++ \
	-DCMAKE_C_FLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero" \
	-DCMAKE_CXX_FLAGS="-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero -I/pytorch_fuzz/torch/csrc/api/include -I/pytorch_fuzz/torch/include -I/libjpeg-turbo-2.1.3-fuzz-afl/" \
	-S . -B build/

cd build/

cmake --build . -j$(nproc)

# Build decode_jpeg_fuzz_afl target

afl-clang-fast++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/libjpeg-turbo-2.1.3-fuzz-afl/ -I/pytorch_fuzz/torch/include \
	/decode_jpeg_fuzz.cc \
	-I/pytorch_fuzz/torch/csrc/api/include -I/vision_fuzz_afl/torchvision/csrc/io/image \
	-I/vision_fuzz_afl/torchvision/csrc/io/image/cpu -c \
	-o ./decode_jpeg_fuzz_afl.o

# Link decode_jpeg_fuzz_afl target

afl-clang-fast++ -g -O2 -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./decode_jpeg_fuzz_afl.o \
	/pytorch_fuzz/torch/lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	/afl.o \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_fuzz_afl/build/libtorchvision.a /pytorch_fuzz/build/lib/libbreakpad.a \
	/pytorch_fuzz/build/lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libqnnpack.a /pytorch_fuzz/torch/lib/libpytorch_qnnpack.a \
	/pytorch_fuzz/torch/lib/libnnpack.a /pytorch_fuzz/torch/lib/libXNNPACK.a \
	/pytorch_fuzz/torch/lib/libpthreadpool.a /pytorch_fuzz/torch/lib/libcpuinfo.a \
	/pytorch_fuzz/torch/lib/libclog.a /pytorch_fuzz/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_fuzz/torch/lib/libkineto.a /pytorch_fuzz/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/build/lib/libonnx_proto.a /pytorch_fuzz/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libjpeg-turbo-2.1.3-fuzz-afl/build/libturbojpeg.a \
	-o /decode_jpeg_fuzz_afl

# Build decode_png_fuzz_afl target

afl-clang-fast++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/pytorch_fuzz/torch/include \
	/decode_png_fuzz.cc \
	-I/pytorch_fuzz/torch/csrc/api/include -I/vision_fuzz_afl/torchvision/csrc/io/image \
	-I/vision_fuzz_afl/torchvision/csrc/io/image/cpu -I/libpng-1.6.37-fuzz-afl/ -c \
	-o ./decode_png_fuzz_afl.o

# Link decode_png_fuzz_afl target

afl-clang-fast++ -g -O2 -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./decode_png_fuzz_afl.o \
	/pytorch_fuzz/torch/lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	/afl.o \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_fuzz_afl/build/libtorchvision.a /pytorch_fuzz/build/lib/libbreakpad.a \
	/pytorch_fuzz/build/lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libqnnpack.a /pytorch_fuzz/torch/lib/libpytorch_qnnpack.a \
	/pytorch_fuzz/torch/lib/libnnpack.a /pytorch_fuzz/torch/lib/libXNNPACK.a \
	/pytorch_fuzz/torch/lib/libpthreadpool.a /pytorch_fuzz/torch/lib/libcpuinfo.a \
	/pytorch_fuzz/torch/lib/libclog.a /pytorch_fuzz/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_fuzz/torch/lib/libkineto.a /pytorch_fuzz/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/build/lib/libonnx_proto.a /pytorch_fuzz/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libpng-1.6.37-fuzz-afl/./.libs/libpng16.a \
	/zlib-1.2.12-fuzz-afl/./libz.a \
	-o /decode_png_fuzz_afl

# Build encode_jpeg_fuzz_afl target

afl-clang-fast++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/libjpeg-turbo-2.1.3-fuzz-afl/ -I/pytorch_fuzz/torch/include \
	/encode_jpeg_fuzz.cc \
	-I/pytorch_fuzz/torch/csrc/api/include -I/vision_fuzz_afl/torchvision/csrc/io/image \
	-I/vision_fuzz_afl/torchvision/csrc/io/image/cpu -c \
	-o ./encode_jpeg_fuzz_afl.o

# Link encode_jpeg_fuzz_afl target

afl-clang-fast++ -g -O2 -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./encode_jpeg_fuzz_afl.o \
	/pytorch_fuzz/torch/lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	/afl.o \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_fuzz_afl/build/libtorchvision.a /pytorch_fuzz/build/lib/libbreakpad.a \
	/pytorch_fuzz/build/lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libqnnpack.a /pytorch_fuzz/torch/lib/libpytorch_qnnpack.a \
	/pytorch_fuzz/torch/lib/libnnpack.a /pytorch_fuzz/torch/lib/libXNNPACK.a \
	/pytorch_fuzz/torch/lib/libpthreadpool.a /pytorch_fuzz/torch/lib/libcpuinfo.a \
	/pytorch_fuzz/torch/lib/libclog.a /pytorch_fuzz/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_fuzz/torch/lib/libkineto.a /pytorch_fuzz/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/build/lib/libonnx_proto.a /pytorch_fuzz/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libjpeg-turbo-2.1.3-fuzz-afl/build/libturbojpeg.a \
	-o /encode_jpeg_fuzz_afl

# Build encode_png_fuzz_afl target

afl-clang-fast++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
	-DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
	-DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
	-DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
	-DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
	-DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
	-DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
	-fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero \
	-I/pytorch_fuzz/torch/include \
	/encode_png_fuzz.cc \
	-I/pytorch_fuzz/torch/csrc/api/include -I/vision_fuzz_afl/torchvision/csrc/io/image \
	-I/vision_fuzz_afl/torchvision/csrc/io/image/cpu -I/libpng-1.6.37-fuzz-afl/ -c \
	-o ./encode_png_fuzz_afl.o

# Link encode_png_fuzz_afl target

afl-clang-fast++ -g -O2 -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero \
	-std=gnu++14 -DNDEBUG \
	./encode_png_fuzz_afl.o \
	/pytorch_fuzz/torch/lib/libtorch.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch.a" -Wl,--no-whole-archive \
	/afl.o \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
	/vision_fuzz_afl/build/libtorchvision.a /pytorch_fuzz/build/lib/libbreakpad.a \
	/pytorch_fuzz/build/lib/libbreakpad_common.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libcaffe2_protos.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libqnnpack.a /pytorch_fuzz/torch/lib/libpytorch_qnnpack.a \
	/pytorch_fuzz/torch/lib/libnnpack.a /pytorch_fuzz/torch/lib/libXNNPACK.a \
	/pytorch_fuzz/torch/lib/libpthreadpool.a /pytorch_fuzz/torch/lib/libcpuinfo.a \
	/pytorch_fuzz/torch/lib/libclog.a /pytorch_fuzz/build/lib/libfoxi_loader.a \
	-lrt -lm -ldl \
	/pytorch_fuzz/torch/lib/libkineto.a /pytorch_fuzz/build/sleef/lib/libsleef.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libonnx.a" -Wl,--no-whole-archive \
	/pytorch_fuzz/build/lib/libonnx_proto.a /pytorch_fuzz/torch/lib/libprotobuf.a \
	-pthread \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx.a" \
	-Wl,--no-whole-archive \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx2.a" \
	-Wl,--no-whole-archive \
	/pytorch_fuzz/torch/lib/libc10.a \
	-Wl,--whole-archive,"/pytorch_fuzz/build/lib/libCaffe2_perfkernels_avx512.a" \
	-Wl,--no-whole-archive \
	/libpng-1.6.37-fuzz-afl/./.libs/libpng16.a \
	/zlib-1.2.12-fuzz-afl/./libz.a \
	-o /encode_png_fuzz_afl
