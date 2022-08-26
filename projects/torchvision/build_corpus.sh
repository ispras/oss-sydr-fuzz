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

# Build and link jpeg tensor saver

cd /vision_sydr/build 

clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
    -DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
    -DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
    -DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
    -DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
    -DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
    -DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
    -I/libjpeg-turbo-2.1.3-sydr/ -I/pytorch_sydr/torch/include \
    /save_jpeg2tensor.cc \
    -I/pytorch_sydr/torch/csrc/api/include -I/vision_sydr/torchvision/csrc/io/image \
    -I/vision_sydr/torchvision/csrc/io/image/cpu -c \
    -o ./save_jpeg.o

clang++ -g -O2 -std=gnu++14 -DNDEBUG \
    ./save_jpeg.o \
    /pytorch_sydr/torch/lib/libtorch.a \
    -Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive \
    -Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
    /vision_sydr/build/libtorchvision.a /pytorch_sydr/build/lib/libbreakpad.a \
    /pytorch_sydr/build/lib/libbreakpad_common.a \
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
    -o /save_jpeg

# Build and link png tensor saver

clang++ -DAT_PER_OPERATOR_HEADERS -DCPUINFO_SUPPORTED_PLATFORM=1 -DFMT_HEADER_ONLY=1 \
    -DFXDIV_USE_INLINE_ASSEMBLY=0 -DHAVE_MALLOC_USABLE_SIZE=1 -DHAVE_MMAP=1 -DHAVE_SHM_OPEN=1 \
    -DHAVE_SHM_UNLINK=1 -DMINIZ_DISABLE_ZIP_READER_CRC32_CHECKS -DNNP_CONVOLUTION_ONLY=0 \
    -DNNP_INFERENCE_ONLY=0 -DONNXIFI_ENABLE_EXT=1 -DONNX_ML=1 -DONNX_NAMESPACE=onnx_torch \
    -DUSE_EXTERNAL_MZCRC -D_FILE_OFFSET_BITS=64 -DUSE_PTHREADPOOL -DNDEBUG -DUSE_KINETO \
    -DLIBKINETO_NOCUPTI -DUSE_QNNPACK -DUSE_PYTORCH_QNNPACK -DUSE_XNNPACK \
    -DSYMBOLICATE_MOBILE_DEBUG_HANDLE -DEDGE_PROFILER_USE_KINETO -DTH_HAVE_THREAD -g -O2 \
    -I/libjpeg-turbo-2.1.3-sydr/ -I/pytorch_sydr/torch/include \
    /save_png2tensor.cc \
    -I/pytorch_sydr/torch/csrc/api/include -I/vision_sydr/torchvision/csrc/io/image \
    -I/vision_sydr/torchvision/csrc/io/image/cpu -c \
    -o ./save_png.o

clang++ -g -O2 -std=gnu++14 -DNDEBUG \
    ./save_png.o \
    /pytorch_sydr/torch/lib/libtorch.a \
    -Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch.a" -Wl,--no-whole-archive \
    -Wl,--whole-archive,"/pytorch_sydr/build/lib/libtorch_cpu.a" -Wl,--no-whole-archive \
    /vision_sydr/build/libtorchvision.a /pytorch_sydr/build/lib/libbreakpad.a \
    /pytorch_sydr/build/lib/libbreakpad_common.a \
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
    /zlib-1.2.12-sydr/./libz.a \
    -o /save_png

# Generate tensors from corpus

cd /

for filename in /jpeg_corpus/*; do ./save_jpeg "$filename"; done
mv /jpeg_corpus/*.tensor /jpeg_tensor/

for filename in /png_corpus/*; do ./save_png "$filename"; done
mv /png_corpus/*.tensor /png_tensor/

# Write \x00 to start of each image file
for filename in /png_corpus/*.png; do
    [ -e "$filename" ] || continue
    printf "\x00" | cat - $filename > ${filename}_input
    rm $filename
done

for filename in /jpeg_corpus/*.jp*g; do
    [ -e "$filename" ] || continue
    printf "\x00" | cat - $filename > ${filename}_input
    rm $filename
done

