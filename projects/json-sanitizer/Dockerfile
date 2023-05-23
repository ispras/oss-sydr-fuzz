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

FROM sydr/ubuntu20.04-jazzer

RUN mkdir /out
RUN git clone --depth 1 https://github.com/google/fuzzing
RUN cat fuzzing/dictionaries/json.dict \
        fuzzing/dictionaries/html.dict \
        fuzzing/dictionaries/xml.dict \
      > /out/DenylistFuzzer.dict
RUN cp fuzzing/dictionaries/json.dict /out/IdempotenceFuzzer.dict
RUN cp fuzzing/dictionaries/json.dict /out/ValidJsonFuzzer.dict
RUN rm -rf fuzzing

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    mv go-fuzz-corpus/json/corpus /out/corpus && rm -rf go-fuzz-corpus

RUN git clone --depth 1 https://github.com/OWASP/json-sanitizer /json-sanitizer

COPY build.sh /json-sanitizer
COPY DenylistFuzzer.java IdempotenceFuzzer.java ValidJsonFuzzer.java /

WORKDIR /json-sanitizer
RUN chmod +x /json-sanitizer/build.sh && /json-sanitizer/build.sh
