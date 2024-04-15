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

RUN git clone https://github.com/aaubry/YamlDotNet.git && \
    cd YamlDotNet && git checkout 19d7875b240c28516ef24c40485e29eaca9b9418

COPY build.sh Program.cs fuzz.csproj yaml.dict /

WORKDIR /

RUN /build.sh
