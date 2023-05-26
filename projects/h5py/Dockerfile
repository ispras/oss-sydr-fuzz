# Copyright 2023 Google Inc.
# Modifications copyright (C) 2023 ISP RAS
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

MAINTAINER Darya Parygina (pa_darochek)

RUN git clone https://github.com/HDFGroup/hdf5 && cd hdf5 && \
    git checkout 509fe962d42b3f02d356d2668b04712df06daf7f

COPY *.sh *.py corpus.zip /

WORKDIR /hdf5

RUN /build_hdf5.sh

RUN pip3 install Cython pkgconfig

WORKDIR /

RUN git clone https://github.com/h5py/h5py && cd h5py && \
    git checkout 3507819de54b35af05b2ca8ca55ec7e7b60cb919

# Fix h5py build.
RUN rm /usr/bin/x86_64-linux-gnu-gcc && \
    ln -s /usr/bin/clang /usr/bin/x86_64-linux-gnu-gcc

WORKDIR /h5py

RUN /build_h5py.sh

WORKDIR /

RUN unzip corpus.zip
