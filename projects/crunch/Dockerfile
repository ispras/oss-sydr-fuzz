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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

MAINTAINER Ilya Yegorov (hkctkuy)

# Install build dependencies.
RUN apt install sudo

# Clone target from GitHub.
RUN git clone https://github.com/chrissimpkins/Crunch.git

WORKDIR /Crunch

# Checkout specified commit. It could be updated later.
RUN git checkout a343532e128bef8d49636b7044b012bf05824658

COPY build.sh \
     optimize_png.py \
     main_single_file.py \
     /

RUN /build.sh
