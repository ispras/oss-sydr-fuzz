# Copyright 2025 ISP RAS
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
RUN cp fuzzing/dictionaries/json.dict /out/json.dict
RUN rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    mv go-fuzz-corpus/json/corpus /out/corpus && rm -rf go-fuzz-corpus

RUN git clone https://github.com/google/gson gson

COPY build.sh /gson
COPY FuzzParse.java FuzzReader.java FuzzStreamParser.java /src/

ENV CASR_SOURCE_DIRS /gson/gson/src/main/java/

WORKDIR /gson
RUN git checkout 0e591c207121fdef26a795096adc8c0076caae21
RUN /gson/build.sh
