# Copyright 2016 Google Inc.
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

RUN apt-get update && apt-get install -y \
	libass-dev libfreetype6-dev libsdl1.2-dev pkg-config libbz2-dev chrpath python \
	libvdpau-dev libxcb1-dev libxcb-xfixes0-dev libxcb-shape0-dev libxcb-shm0-dev libdrm-dev \
	texinfo libbz2-dev libbz2-1.0 zlib1g zlib1g-dev yasm mercurial \
	xutils-dev libpciaccess-dev nasm rsync libvpx-dev

RUN curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb && \
    apt install ./automake_1.16.5-1.3_all.deb

RUN git clone https://github.com/FFmpeg/FFmpeg.git ffmpeg
RUN wget https://www.alsa-project.org/files/pub/lib/alsa-lib-1.1.0.tar.bz2
RUN git clone https://github.com/mstorsjo/fdk-aac.git
RUN git clone https://github.com/intel/libva
RUN git clone -b libvdpau-1.2 git://people.freedesktop.org/~aplattner/libvdpau
RUN git clone https://chromium.googlesource.com/webm/libvpx
RUN git clone https://gitlab.xiph.org/xiph/ogg.git
RUN git clone https://gitlab.xiph.org/xiph/opus.git
RUN git clone https://gitlab.xiph.org/xiph/theora.git
RUN git clone https://gitlab.xiph.org/xiph/vorbis.git
RUN git clone https://gitlab.gnome.org/GNOME/libxml2.git

COPY *.sh *.py target* /

RUN CONFIG="libfuzzer" /build.sh
RUN CONFIG="afl" /build.sh
RUN CONFIG="sydr" /build.sh
RUN CONFIG="coverage" /build.sh
