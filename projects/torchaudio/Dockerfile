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

# Clone pytorch and torchaudio from GitHub.
RUN git clone https://github.com/pytorch/pytorch.git pytorch
RUN cd /pytorch && \
    git checkout 0f1621df1a0a73956c7ce4e2f72f069e610e0137 && \
    git submodule update --init --recursive --jobs 0

COPY torchaudio.patch /
RUN git clone https://github.com/pytorch/audio.git audio
RUN cd /audio && \
    git checkout 30afaa9b2f460ca3baf6ac177bce4f6b5da8b99c && \
    git apply /torchaudio.patch

COPY build.sh torchaudio.patch /
COPY load_audio.cc /audio

RUN CONFIGS="libfuzzer afl" /build.sh
RUN CONFIGS="sydr coverage" /build.sh

# Prepare corporas.
RUN mkdir wav_corpus
RUN git clone https://github.com/strongcourage/fuzzing-corpus.git && \
    find /fuzzing-corpus -name '*.wav' -exec cp {} /wav_corpus/ \;
