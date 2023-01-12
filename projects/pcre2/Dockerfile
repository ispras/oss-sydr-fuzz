# Copyright 2022 ISP RAS
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

FROM sydr/ubuntu20.04-sydr-fuzz

RUN git clone https://github.com/PCRE2Project/pcre2

WORKDIR pcre2

RUN git checkout 0746b3d523c9a799aa62ae9e03188b23664f48b0

RUN mkdir /corpus && cp testdata/* /corpus/

COPY build.sh .

RUN bash build.sh

WORKDIR /
