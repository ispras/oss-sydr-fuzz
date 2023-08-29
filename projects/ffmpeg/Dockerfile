# Copyright 2016 Google Inc.
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

RUN apt-get update && apt-get install -y \
	libass-dev libfreetype6-dev libsdl1.2-dev pkg-config libbz2-dev chrpath python \
	libvdpau-dev libxcb1-dev libxcb-xfixes0-dev libxcb-shape0-dev libxcb-shm0-dev libdrm-dev \
	texinfo libbz2-dev libbz2-1.0 zlib1g zlib1g-dev yasm mercurial \
	xutils-dev libpciaccess-dev nasm rsync libvpx-dev lib32z1 gcc-multilib

RUN curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb && \
    apt install ./automake_1.16.5-1.3_all.deb

RUN git clone https://github.com/FFmpeg/FFmpeg.git ffmpeg && cd ffmpeg && \
	git checkout f225f8d7464569c7b917015c26ad30a37a5fbbe2
RUN wget https://www.alsa-project.org/files/pub/lib/alsa-lib-1.1.0.tar.bz2
RUN git clone https://github.com/mstorsjo/fdk-aac.git && cd fdk-aac && \
	git checkout 3f864cce9736cc8e9312835465fae18428d76295
RUN git clone https://github.com/intel/libva && cd libva && \
	git checkout 7d6c7d482b9d2330b1f3a8bac13a6a3205f33382
RUN git clone -b libvdpau-1.2 git://people.freedesktop.org/~aplattner/libvdpau
RUN git clone https://chromium.googlesource.com/webm/libvpx && cd libvpx && \
	git checkout 24c0dcc8513b8c1ba4ffbf934a399f89de646ffe
RUN git clone https://gitlab.xiph.org/xiph/ogg.git && cd ogg && \
	git checkout db5c7a49ce7ebda47b15b78471e78fb7f2483e22
RUN git clone https://gitlab.xiph.org/xiph/opus.git && cd opus && \
	git checkout 9fc8fc4cf432640f284113ba502ee027268b0d9f
RUN git clone https://gitlab.xiph.org/xiph/theora.git && cd theora && \
	git checkout 7180717276af1ebc7da15c83162d6c5d6203aabf
RUN git clone https://gitlab.xiph.org/xiph/vorbis.git && cd vorbis && \
	git checkout 84c023699cdf023a32fa4ded32019f194afcdad0
RUN git clone https://gitlab.gnome.org/GNOME/libxml2.git && cd libxml2 && \
	git checkout 778cca386dd29893958310576792e08e018f8e23

COPY *.sh *.py /

RUN CONFIG="libfuzzer" /build.sh
RUN CONFIG="afl" /build.sh
RUN CONFIG="sydr" /build.sh
RUN CONFIG="coverage" /build.sh
