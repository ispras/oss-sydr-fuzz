# Copyright 2020 Google LLC
# Modifications copyright (C) 2022 ISP RAS
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

FROM gcr.io/oss-fuzz-base/base-builder-python

# library build dependencies
RUN apt-get update && \
    apt-get install -y \
      libxau-dev \
      pkg-config \
      rsync \
      pip \
      vim \
      clang

RUN pip install coverage

WORKDIR /

RUN git clone https://github.com/python-pillow/Pillow
RUN git clone https://github.com/python-pillow/pillow-wheels

RUN /Pillow/Tests/oss-fuzz/build_dictionaries.sh

COPY build_depends.sh /

RUN ln -s /usr/local/bin/python3 /usr/local/bin/python \
    && ln -s /bin/true /usr/local/bin/yum_install \
    && ln -s /bin/true /usr/local/bin/yum \
    && cd /pillow-wheels \
    && git submodule update --init multibuild \
    && bash /build_depends.sh

# install extra test images for a better starting corpus
RUN cd Pillow && depends/install_extra_test_images.sh

# pillow optional runtime dependencies
RUN apt-get install -y \
     python3-tk \
     tcl8.6-dev \
     tk8.6-dev

WORKDIR /Pillow

COPY build.sh /

RUN /build.sh

RUN unzip /out/fuzz_font_seed_corpus.zip \
    -d /out/fuzz_font_seed_corpus \
    && unzip /out/fuzz_pillow_seed_corpus.zip \
    -d /out/fuzz_pillow_seed_corpus
