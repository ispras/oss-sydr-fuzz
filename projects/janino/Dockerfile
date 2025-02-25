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

RUN git clone https://github.com/janino-compiler/janino.git janino

COPY build.sh /janino
COPY ExpressionEvaluatorFuzzer.java /src/

ENV CASR_SOURCE_DIRS /janino/janino/src/main/java/

WORKDIR /janino
RUN git checkout 4db1b8117bda36056f4eeab2d29e1f524b21b13c
RUN /janino/build.sh
