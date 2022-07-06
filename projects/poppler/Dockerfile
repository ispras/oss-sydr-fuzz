# Copyright 2018 Google Inc.
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

FROM sweetvishnya/ubuntu20.04-sydr-fuzz

MAINTAINER Ilya Yegorov (hkctkuy)

# Build targets for libfuzzer

WORKDIR /src/libfuzzer

# Install build dependencies.
RUN apt-get update && apt-get install -y wget autoconf automake libtool pkg-config gperf
RUN apt-get install python -y
RUN apt-get install zip
RUN pip3 install meson ninja gyp-next
RUN git clone https://github.com/madler/zlib.git
RUN git clone https://gitlab.freedesktop.org/freetype/freetype.git
RUN git clone https://github.com/mm2/Little-CMS.git
RUN git clone https://github.com/uclouvain/openjpeg
RUN git clone https://github.com/glennrp/libpng.git
RUN git clone https://gitlab.freedesktop.org/fontconfig/fontconfig.git
RUN git clone https://gitlab.freedesktop.org/cairo/cairo.git
RUN git clone --branch=5.15 git://code.qt.io/qt/qtbase.git
RUN git clone https://gitlab.gnome.org/GNOME/pango.git
ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.73/glib-2.73.1.tar.xz .
RUN tar xvJf ./glib-2.73.1.tar.xz
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2
RUN wget https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_75_RTM/src/nss-3.75-with-nspr-4.32.tar.gz
RUN git clone https://gitlab.freedesktop.org/poppler/poppler.git

RUN git clone https://github.com/mozilla/pdf.js pdf.js && \
    mkdir -p /out/corpus && \
    cp pdf.js/test/pdfs/*.pdf /out/corpus && \
    rm -rf pdf.js
ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/pdf.dict /out/poppler.dict

WORKDIR /src/libfuzzer/poppler

# Checkout specified commit. It could be updated later.
RUN git checkout 4139f79cf8c4e3f529570c9a300491c36f9100e8

COPY build_fuzzer.sh \
     ./

RUN ./build_fuzzer.sh

# Build targets for sydr

WORKDIR /src/sydr

# Install build dependencies.
RUN git clone https://github.com/madler/zlib.git
RUN git clone https://gitlab.freedesktop.org/freetype/freetype.git
RUN git clone https://github.com/mm2/Little-CMS.git
RUN git clone https://github.com/uclouvain/openjpeg
RUN git clone https://github.com/glennrp/libpng.git
RUN git clone https://gitlab.freedesktop.org/fontconfig/fontconfig.git
RUN git clone https://gitlab.freedesktop.org/cairo/cairo.git
RUN git clone --branch=5.15 git://code.qt.io/qt/qtbase.git
RUN git clone https://gitlab.gnome.org/GNOME/pango.git
ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.73/glib-2.73.1.tar.xz .
RUN tar xvJf ./glib-2.73.1.tar.xz
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2
RUN wget https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_75_RTM/src/nss-3.75-with-nspr-4.32.tar.gz
RUN git clone https://gitlab.freedesktop.org/poppler/poppler.git

WORKDIR /src/sydr/poppler

# Checkout specified commit. It could be updated later.
RUN git checkout 4139f79cf8c4e3f529570c9a300491c36f9100e8

COPY main.c \
     ./

COPY build_sydr.sh \
     ./

RUN ./build_sydr.sh

# Build targets for llvm-cov

WORKDIR /src/cov

# Install build dependencies.
RUN git clone https://github.com/madler/zlib.git
RUN git clone https://gitlab.freedesktop.org/freetype/freetype.git
RUN git clone https://github.com/mm2/Little-CMS.git
RUN git clone https://github.com/uclouvain/openjpeg
RUN git clone https://github.com/glennrp/libpng.git
RUN git clone https://gitlab.freedesktop.org/fontconfig/fontconfig.git
RUN git clone https://gitlab.freedesktop.org/cairo/cairo.git
RUN git clone --branch=5.15 git://code.qt.io/qt/qtbase.git
RUN git clone https://gitlab.gnome.org/GNOME/pango.git
ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.73/glib-2.73.1.tar.xz .
RUN tar xvJf ./glib-2.73.1.tar.xz
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2
RUN wget https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_75_RTM/src/nss-3.75-with-nspr-4.32.tar.gz
RUN git clone https://gitlab.freedesktop.org/poppler/poppler.git

WORKDIR /src/cov/poppler

# Checkout specified commit. It could be updated later.
RUN git checkout bb1651334abc11495fa0326c8d562243d2a4b055

COPY main.c \
     ./

COPY build_cov.sh \
     ./

RUN ./build_cov.sh
