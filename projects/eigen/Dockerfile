# Copyright 2019 Google Inc.
# Modifications copyright (C) 2025 ISP RAS
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

RUN apt-get update && apt-get install --yes cmake mercurial
# checkout to latest commit that passed all pipeline stages
RUN git clone https://gitlab.com/libeigen/eigen.git && cd eigen && git checkout 6de0515fa6b923a8fc1436e3b8c6f2a4ce565484

COPY build.sh *.cc /
COPY corpus_solver.tar.xz /corpus_solver.tar.xz
COPY corpus_basicstuff.tar.xz /corpus_basicstuff.tar.xz

# unzip corpus and rm archives
RUN tar --extract corpus_solver -f corpus_solver.tar.xz && tar --extract corpus_basicstuff -f corpus_basicstuff.tar.xz && rm corpus_solver.tar.xz corpus_basicstuff.tar.xz

RUN /build.sh
