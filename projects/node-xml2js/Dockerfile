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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

# Install build dependencies.
WORKDIR /jazzer.js
RUN npm install xml2js@0.6.2
ENV PATH=$PATH:/jazzer.js/fuzz/sydr

# Clone target from GitHub.
RUN git clone https://github.com/Leonidas-from-XIV/node-xml2js && \
    cd node-xml2js && git checkout cf3e061e22e98152b88068c2345bc02581f4d6c7

# Copy build script and targets.
COPY fuzz.js node-xml2js/
RUN chmod +x node-xml2js/fuzz.js

# Prepare seed corpus and dict.
COPY xml.dict /
RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git /go-fuzz-corpus
RUN cp -r /go-fuzz-corpus/xml/corpus /corpus
