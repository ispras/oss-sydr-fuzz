# Copyright 2017 Google Inc.
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

MAINTAINER Alexey Vishnyakov

RUN apt-get update && apt-get install -y make autoconf automake libtool pkg-config

RUN git clone https://github.com/leethomason/tinyxml2

WORKDIR tinyxml2

RUN git checkout e45d9d16d430a3f5d3eee9fe40d5e194e1e5e63a

COPY build.sh main.c ./
COPY xmltest.cpp ./fuzz.cpp

RUN ./build.sh

WORKDIR /

RUN mkdir /corpus && find tinyxml2 -name "*.xml" | xargs -I {} cp {} /corpus
