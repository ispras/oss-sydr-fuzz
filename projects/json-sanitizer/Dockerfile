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

RUN mkdir /src && mkdir /out

RUN git clone --depth 1 https://github.com/google/fuzzing
RUN cat fuzzing/dictionaries/json.dict \
        fuzzing/dictionaries/html.dict \
        fuzzing/dictionaries/xml.dict \
      > /out/DenylistFuzzerJZ.dict
RUN cp fuzzing/dictionaries/json.dict /out/IdempotenceFuzzerJZ.dict
RUN cp fuzzing/dictionaries/json.dict /out/ValidJsonFuzzerJZ.dict
RUN rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    mv go-fuzz-corpus/json/corpus /out/corpus && rm -rf go-fuzz-corpus

RUN git clone https://github.com/OWASP/json-sanitizer /json-sanitizer

COPY build.sh /json-sanitizer
COPY DenylistFuzzerJZ.java IdempotenceFuzzerJZ.java ValidJsonFuzzerJZ.java /src
COPY DenylistFuzzerJF.java IdempotenceFuzzerJF.java ValidJsonFuzzerJF.java /json-sanitizer/src/main/java/com/google/json
COPY pom.patch /json-sanitizer

ENV CASR_SOURCE_DIRS=/json-sanitizer/src/main/java:/out/gson-2.8.6-src/

WORKDIR /json-sanitizer
RUN git checkout 6c86f9becc3412167e912384832722a5ebe69b12
RUN git apply pom.patch
RUN mvn clean package -DskipTests -Dmaven.javadoc.skip=true

WORKDIR /

RUN /json-sanitizer/build.sh
