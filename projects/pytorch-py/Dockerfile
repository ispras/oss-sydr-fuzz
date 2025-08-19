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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

# Install build dependencies.
RUN pip3 install astunparse numpy ninja pyyaml mkl mkl-include setuptools cffi typing_extensions

# Clone target from GitHub.
RUN git clone https://github.com/pytorch/pytorch/ /pytorch
RUN cd /pytorch && \
    git checkout v2.8.0 && \
    git submodule update --init --recursive --jobs 0

# Copy build script and targets.
COPY *.sh \
     *.py \
     *.zip \
     /

# Fix PyTorch build.
RUN rm /usr/bin/x86_64-linux-gnu-gcc && \
    ln -s /usr/bin/clang /usr/bin/x86_64-linux-gnu-gcc

# Build PyTorch, torchvision and torchtext.
RUN /build_torch.sh

# Prepare initial corporas.
RUN unzip load_fuzz.zip
RUN mkdir /parse_native_yaml && \
    find /pytorch/aten/src/ATen/native -name "*.yaml" | xargs -I {} cp {} /parse_native_yaml
