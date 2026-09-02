# Copyright 2025 ISP RAS
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

ARG BASE_IMAGE="sydr/ubuntu22.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN apt-get update && \
    apt-get install -y yasm nasm libuv1-dev pybind11-dev
RUN pip3 install pybind11

# Clone target from GitHub.
RUN git clone https://github.com/pytorch/pytorch /pytorch
RUN cd /pytorch && git checkout v2.13.0 && git submodule sync && \
    git submodule update --init --recursive

# Get TorchCodec
RUN git clone -b v0.16.0 https://github.com/meta-pytorch/torchcodec

# Get image libraries: libjpeg, libpng, libwebp, libheif, libavif
RUN git clone https://github.com/libjpeg-turbo/libjpeg-turbo.git && \
    cd /libjpeg-turbo && git checkout 3.2.0
RUN git clone https://github.com/pnggroup/libpng.git && \
    cd /libpng && git checkout v1.6.58
RUN git clone https://github.com/webmproject/libwebp.git && \
    cd /libwebp && git checkout v1.6.0
RUN git clone https://github.com/strukturag/libheif.git && \
    cd /libheif && git checkout v1.23.2
RUN git clone https://github.com/AOMediaCodec/libavif.git && \
    cd /libavif && git checkout v1.4.2
RUN git clone https://github.com/madler/zlib.git zlib && \
    cd zlib && git checkout v1.3.2

# Copy build scripts.
COPY *.sh \
     *.patch \
    /

# Patch exceptions throwing to avoid unwanted crashes.
RUN ./patch_exceptions.sh

# Fix PyTorch build.
RUN rm /usr/bin/x86_64-linux-gnu-gcc && \
    ln -s /usr/bin/clang /usr/bin/x86_64-linux-gnu-gcc
RUN cd /pytorch/third_party/NNPACK && git apply /NNPACK_CMakeLists.patch
ENV PATH "/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/fuzz/sydr:/usr/local/go/bin:/root/go/bin:/root/.dotnet/tools"
RUN ln -s /usr/bin/python3 /usr/bin/python
RUN cd /pytorch && pip3 install --group dev

# Patch TorchCodec
COPY fuzz_targets/image_decoders.cc /torchcodec/src/torchcodec/_core/
RUN rm /torchcodec/src/torchcodec/_core/CMakeLists.txt
COPY image_cmakelists.txt /torchcodec/src/torchcodec/_core/CMakeLists.txt

# Build    
RUN TARGET="fuzzer" /build.sh
RUN TARGET="afl" /build.sh
RUN TARGET="sydr" /build.sh
RUN TARGET="cov" /build.sh

# Prepare corpus
RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git
RUN git clone https://github.com/ImageGlass/sample-images.git
RUN for fmt in "jpeg" "jpg" "png" "webp" "gif" "heic" "avif"; \
    do \
        mkdir /corpus_${fmt}; \
        find /torchcodec   -name "*.${fmt}" -type f | xargs -I {} cp {} /corpus_${fmt}; \
        find /sample-images -name "*.${fmt}" -type f | xargs -I {} cp {} /corpus_${fmt}; \
        find /libjpeg-turbo /libpng /libwebp /libheif /libavif -name "*.${fmt}" -type f | xargs -I {} cp {} /corpus_${fmt}; \
        cp /go-fuzz-corpus/${fmt}/corpus/* /corpus_${fmt}/. || echo 1; \
    done
RUN cp /corpus_jpg/* /corpus_jpeg/. && rm -rf /corpus_jpg
RUN find corpus_* -type f -empty -delete
COPY crashes_jpeg.zip /
RUN unzip -q crashes_jpeg.zip && rm crashes_jpeg.zip && mv crashes_jpeg/* /corpus_jpeg/.
RUN rm -rf /sample-images /go-fuzz-corpus /crashes_jpeg

