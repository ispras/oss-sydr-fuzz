# Copyright (C) 2025 ISP RAS
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

RUN apt install -y mercurial

# Clone repo for the corpus
RUN git clone https://github.com/yaml/libyaml

RUN hg clone http://hg.code.sf.net/p/ruamel-yaml/code ruamel-yaml

WORKDIR /ruamel-yaml

# Checkout specified commit. It could be updated later.
RUN hg checkout 54d2c5

RUN rustup toolchain uninstall nightly && rustup toolchain install nightly && rustup update

RUN pip install python-afl==0.7.3

COPY build.sh \
     yaml_fuzzer_*.py \
     yaml.dict \
     /

RUN /build.sh
