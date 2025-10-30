# Copyright 2024 ISP RAS
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

RUN wget https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.4/apache-maven-3.9.4-bin.tar.gz && \
    tar -xvf apache-maven-*-bin.tar.gz && \
    rm apache-maven-*-bin.tar.gz && \
    mv apache-maven-* /opt/maven && \
    ln -s /opt/maven/bin/mvn /usr/local/bin/mvn

RUN wget -O jacocoagent.jar https://github.com/fuzzitdev/javafuzz/raw/master/javafuzz-maven-plugin/src/main/resources/jacocoagent-exp.jar

RUN mkdir /src && mkdir /out

RUN git clone https://github.com/java-diff-utils/java-diff-utils java-diff-utils

RUN git clone https://github.com/fuzzitdev/javafuzz.git javafuzz

ENV CASR_SOURCE_DIRS=/java-diff-utils/java-diff-utils/src/main/java/

COPY pom.patch /java-diff-utils
WORKDIR /java-diff-utils
RUN git checkout 903982517a747d012639c85bdbe05721f88b86d9
RUN git apply pom.patch

WORKDIR /
COPY build.sh /java-diff-utils
COPY DiffUtilsFuzzerJZ.java /src
COPY DiffUtilsFuzzerJF.java /java-diff-utils/java-diff-utils/src/test/java/com/github/difflib

RUN /java-diff-utils/build.sh

