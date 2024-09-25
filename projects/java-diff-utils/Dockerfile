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

FROM sydr/ubuntu20.04-sydr-fuzz

RUN mkdir /src && mkdir /out

RUN git clone https://github.com/java-diff-utils/java-diff-utils java-diff-utils

COPY build.sh /java-diff-utils
COPY DiffUtilsFuzzer.java /src

ENV CASR_SOURCE_DIRS /java-diff-utils/java-diff-utils/src/main/java/

WORKDIR /java-diff-utils
RUN git checkout 903982517a747d012639c85bdbe05721f88b86d9
RUN /java-diff-utils/build.sh
