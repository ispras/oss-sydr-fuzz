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

FROM sydr/ubuntu20.04-sydr-fuzz

# Install build dependencies.
RUN pip3 install astunparse numpy ninja pyyaml mkl mkl-include setuptools cmake cffi typing_extensions

# Clone target from GitHub.
RUN git clone https://github.com/pytorch/pytorch/ /pytorch
RUN cd /pytorch && \
    git checkout 22e2fd554cf370765d4c44fe2b99c8bb6e42b0bb && \
    git submodule update --init --recursive --jobs 0

RUN git clone https://github.com/pytorch/vision/ /vision
RUN cd /vision && \
    git checkout 1f4a98468a74f3f3739fc05bd15a014b3f8b1fab && \
    git submodule update --init --recursive --jobs 0

RUN git clone https://github.com/pytorch/text /text
RUN cd /text && \
    git checkout 9a7bf8b643274e10e10c419a352fd41bb4a8c1c4 && \
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

RUN /build_vision.sh

RUN /build_text.sh

# Prepare initial corporas.
RUN unzip load_fuzz.zip
