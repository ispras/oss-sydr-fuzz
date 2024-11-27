# Copyright 2024 ISP RAS
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

RUN git clone https://github.com/mono/CppSharp.git && \
    cd CppSharp && git checkout 81e0a931cf6116951e37b0fa763e1974bc753a83

RUN git clone https://github.com/Mooophy/Cpp-Primer.git && \
    cd Cpp-Primer && git checkout abcb44b77668abaca539c482d359d17f5a0e3d7f

COPY build.sh Parser.cs fuzz.csproj /

WORKDIR /

RUN /build.sh

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/CppSharp/bin/Release_x64/
