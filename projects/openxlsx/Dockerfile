# Copyright (C) 2022 ISP RAS
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

FROM sweetvishnya/ubuntu20.04-sydr-fuzz

MAINTAINER Andrey Fedotov

# Clone target from GitHub.
RUN git clone  https://github.com/troldal/OpenXLSX.git openxlsx

WORKDIR /openxlsx

# Checkout commit
RUN git checkout 3eb9c748e3ecd865203fb9946ea86d3c02b3f7d9

# Copy build script and targets.
COPY build.sh \
     fuzzer.cc \
     sydr.cc \
     xlst.dict \
     /

# Build fuzz targets.
RUN ../build.sh

WORKDIR /
