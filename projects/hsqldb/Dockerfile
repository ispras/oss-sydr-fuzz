# Copyright 2023 ISP RAS
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

RUN curl -L https://dlcdn.apache.org//ant/binaries/apache-ant-1.10.14-bin.zip -o ant.zip && \
    unzip ant.zip -d /ant && \
    rm -rf ant.zip

RUN apt install -y subversion

RUN svn checkout https://svn.code.sf.net/p/hsqldb/svn/base/trunk hsqldb-svn

COPY build.sh /
COPY *.java /
WORKDIR /hsqldb

RUN /build.sh
