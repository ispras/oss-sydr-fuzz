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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

WORKDIR /

# Clone pytorch, torchaudio and libsox from GitHub.
RUN git clone https://github.com/pytorch/pytorch.git pytorch
RUN cd /pytorch && \
    git checkout 19ae5afdaa3a59135e6adbaea197b7a2456f1865 && \
    git submodule sync && \
    git submodule update --init --recursive --jobs 0 && \
    sed -i '/^cmake$/d' requirements.txt && \
    pip install -r requirements.txt

COPY torchaudio.patch /
RUN git clone https://github.com/pytorch/audio.git audio
RUN cd /audio && \
    git checkout 70caf76066ef2c1054d6128b11769dc816a779e7 && \
    git apply /torchaudio.patch

COPY libsox.patch /
RUN git clone git://git.code.sf.net/p/sox/code /libsox
RUN cd /libsox && \
    git checkout 42b3557e13e0fe01a83465b672d89faddbe65f49 && \
    git apply /libsox.patch

COPY build.sh /
COPY load_audio.cc /audio

RUN CONFIGS="libfuzzer" /build.sh
RUN CONFIGS="sydr" /build.sh
RUN CONFIGS="coverage" /build.sh
RUN CONFIGS="afl" /build.sh

# Prepare corporas.
RUN mkdir wav_corpus
RUN git clone https://github.com/strongcourage/fuzzing-corpus.git && \
    find /fuzzing-corpus -name '*.wav' -exec cp {} /wav_corpus/ \;
