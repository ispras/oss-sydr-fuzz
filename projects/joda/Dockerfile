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

RUN git clone https://github.com/JodaOrg/joda-time joda-time

COPY build.sh /joda-time
COPY TimeFuzzer.java /src/

ENV CASR_SOURCE_DIRS /joda-time/src/main/java 

WORKDIR /joda-time
RUN git checkout 15c3df573457a34e36d4b918e114d9c2d7e45396
RUN /joda-time/build.sh
