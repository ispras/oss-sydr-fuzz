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

FROM sweetvishnya/ubuntu20.04-sydr-fuzz

MAINTAINER Kirill Parhomenko

# Install build dependencies.
RUN pip3 install astunparse numpy ninja pyyaml mkl mkl-include setuptools cmake cffi typing_extensions 

# Clone target from GitHub.
RUN git clone https://github.com/pytorch/pytorch.git pytorch_fuzz
RUN cd /pytorch_fuzz && \
    git checkout bc2c6edaf163b1a1330e37a6e34caf8c553e4755 && \
    git submodule update --init --recursive --jobs 0

# Copy build script and targets.
COPY build_*.sh \
     *.patch \
     miniz.* \
     *_fuzz.cc \
     *_sydr.cc \
     *.toml \
     /

# Apply PyTorch fixes.
RUN cd /pytorch_fuzz && \
    git apply /stoull.patch
RUN rm /pytorch_fuzz/third_party/miniz-2.0.8/miniz.*
RUN cp miniz.* /pytorch_fuzz/third_party/miniz-2.0.8/.

# Copy for different targets.
RUN cp -r /pytorch_fuzz/ /pytorch_sydr/
RUN cp -r /pytorch_fuzz/ /pytorch_cov/

# Build fuzz targets.
RUN bash build_fuzz.sh
RUN bash build_sydr.sh
RUN bash build_cov.sh

RUN mkdir corpus && find /pytorch_fuzz -name "*.pt" -exec cp {} ./corpus \;
