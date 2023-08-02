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

MAINTAINER Kobrin Eli

# Clone pytorch, torchaudio and libsox from GitHub.
RUN git clone https://github.com/pytorch/pytorch.git pytorch
RUN cd /pytorch && \
    git checkout 0f1621df1a0a73956c7ce4e2f72f069e610e0137 && \
    git submodule update --init --recursive --jobs 0

COPY torchaudio.patch /
RUN git clone https://github.com/pytorch/audio.git audio
RUN cd /audio && \
    git checkout 8497ee91b7526b5734e0cc16f9a0afafd9e72e78 && \
    git apply /torchaudio.patch

COPY libsox.patch /
RUN git clone git://git.code.sf.net/p/sox/code /libsox
RUN cd /libsox && \
    git checkout 42b3557e13e0fe01a83465b672d89faddbe65f49 && \
    git apply /libsox.patch

COPY build.sh /
COPY load_audio.cc /audio

# Build libsox
RUN cd /libsox && \
    autoreconf -i && \
    ./configure && \
    make && \
    make install
ENV LD_LIBRARY_PATH=/libsox/src/.libs

RUN CONFIGS="libfuzzer afl" /build.sh
RUN CONFIGS="sydr coverage" /build.sh

# Prepare corporas.
RUN mkdir wav_corpus
RUN git clone https://github.com/strongcourage/fuzzing-corpus.git && \
    find /fuzzing-corpus -name '*.wav' -exec cp {} /wav_corpus/ \;
