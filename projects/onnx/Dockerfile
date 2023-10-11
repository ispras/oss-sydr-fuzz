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

RUN apt install -y protobuf-compiler

# Clone target from GitHub.
RUN git clone https://github.com/onnx/onnx.git /onnx
RUN cd /onnx && \
    git checkout 1014f41f17ecc778d63e760a994579d96ba471ff && \
    git submodule update --init --recursive --jobs 0

# Copy build script and targets.
COPY *.sh \
     *.cc \
     *.h \
     /

# Install protobuf.
RUN git clone https://github.com/protocolbuffers/protobuf.git /protobuf
RUN cd /protobuf && \
    git checkout v21.12 && \
    git submodule update --init --recursive && /build_protobuf.sh

# Build fuzz targets.
RUN TARGET="afl" /build.sh
RUN TARGET="fuzz" /build.sh
RUN TARGET="sydr" /build.sh
RUN TARGET="cov" /build.sh

# Prepare corpus.
RUN mkdir /corpus && \
    wget https://github.com/onnx/models/blob/69c5d3751dda5349fd3fc53f525395d180420c07/vision/classification/alexnet/model/bvlcalexnet-12-int8.onnx -P /corpus && \
    for file in `find /onnx -name "*.onnx"`; do cp $file /corpus/$(basename `dirname $file`)_$(basename $file); done
