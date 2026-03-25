# Copyright 2025 Google LLC
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

RUN apt-get update && apt-get install -y autoconf automake libsodium-dev libgtest-dev

RUN git clone https://github.com/BehaviorTree/BehaviorTree.CPP.git behaviortreecpp \
    && cd behaviortreecpp \
    && git checkout 3ff6a32ba0497a08519c77a1436e3b81eff1bcd6

WORKDIR /behaviortreecpp

COPY build.sh /

RUN TARGET="fuzzer" /build.sh
RUN TARGET="sydr"   /build.sh
RUN TARGET="cov"    /build.sh
