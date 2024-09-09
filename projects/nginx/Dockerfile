# Copyright 2020 Google Inc.
# Modifications copyright (C) 2024 ISP RAS
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

# UPDATE + dep for nginx, preeny
RUN apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get install -y \
    libpcre3-dev zlib1g-dev mercurial ninja-build liblzma-dev \
    libz-dev binutils libtool build-essential libssl-dev libseccomp-dev \
    libini-config-dev \
    && apt-get autoclean

# ansifilter
ARG GIT_ANSIFILTER_TAG="2.18"
ARG ANSIFILTER_SRC_DIR="/ansifilter"
RUN git clone --depth=1 https://gitlab.com/saalen/ansifilter.git \
    -b ${GIT_ANSIFILTER_TAG} ${ANSIFILTER_SRC_DIR}

# geckodriver for selenium
RUN cd /usr/bin \
    && curl https://github.com/mozilla/geckodriver/releases/download/v0.33.0/geckodriver-v0.33.0-linux64.tar.gz -L \
    | tar zxv

# Settings
RUN echo -e "set -g mouse on\nset -g mode-mouse on\n" > /etc/tmux.conf \
    && sh -c 'echo set encoding=utf-8 > /root/.vimrc' \
    && echo '. /usr/share/bash-completion/bash_completion' >> ~/.bashrc \
    && echo "export PS1='"'[fuzzuser \h] \w \$ '"'" >> ~/.bashrc \
    && git config --global advice.detachedHead false

# Clone target from GitHub. Checkout specified commit. It could be updated later.
RUN hg clone http://hg.nginx.org/nginx/ -u d1b8568f3042 /nginx

# preeny
RUN git clone https://github.com/zardus/preeny.git

# Prepare seed corpora
RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git /go-fuzz-corpus && \
    cp -r /go-fuzz-corpus/http2/corpus /corpus_auth && \
    cp /go-fuzz-corpus/httpreq/corpus/* /corpus_auth && \
    rm /corpus_auth/da39a3ee5e6b4b0d3255bfef95601890afd80709-2 && \
    rm /corpus_auth/da39a3ee5e6b4b0d3255bfef95601890afd80709-1 && \
    rm -rf /go-fuzz-corpus
COPY auth_fuzz/inputs.zip /
RUN unzip /inputs.zip -d /corpus_auth
RUN rm /inputs.zip
# Duplicate file contents to use it for request and reply.
RUN cp -r /corpus_auth /corpus_request
RUN for file in /corpus_request/*; do echo `cat $file` >>$file; done;

# Save fuzz target and additional files for libFuzzer, AFL++, and Sydr builds.
RUN mkdir /nginx/src/request_fuzz
COPY request_fuzz /nginx/src/request_fuzz/
COPY request_fuzz/http_request_fuzzer.dict request_fuzz/http_config.conf /

# Build http_request fuzz targets.
RUN /nginx/src/request_fuzz/build.sh

# Save fuzz target and additional files for libFuzzer, AFL++, and Sydr builds.
RUN mkdir /nginx/src/auth_fuzz
COPY auth_fuzz /nginx/src/auth_fuzz/
COPY auth_fuzz/auth_config.conf nginx/conf/nginx.conf
COPY auth_fuzz/auth_config.conf /usr/local/nginx/conf/nginx.conf

ENV AFL_USE_ASAN=1

# Build auth fuzz targets.
RUN /nginx/src/auth_fuzz/build.sh /nginx/ /nginx/src/auth_fuzz/ all
