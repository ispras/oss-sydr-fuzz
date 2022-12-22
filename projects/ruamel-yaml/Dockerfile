# Copyright (C) 2022 ISP RAS
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

# Clone repo for the corpus
RUN git clone https://github.com/yaml/libyaml

WORKDIR /libyaml

# Checkout specified commit. It could be updated later.
RUN git checkout acd6f6f014c25e46363e718381e0b35205df2d83

WORKDIR /ruamel-yaml

COPY build.sh \
     yaml_fuzzer.py \
     /

RUN /build.sh
