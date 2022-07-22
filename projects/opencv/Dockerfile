# Copyright 2018 Google Inc.
# Modifications copyright (C) 2022 ISP RAS
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

RUN apt-get update && apt-get install -y build-essential cmake pkg-config

RUN git clone https://github.com/opencv/opencv.git opencv

WORKDIR /opencv/

RUN git checkout a42b35598e2543d6dab3ac73be92fb77742e0747

COPY build.sh /opencv/

COPY *.cc *.c *.h /opencv/

RUN /opencv/build.sh
