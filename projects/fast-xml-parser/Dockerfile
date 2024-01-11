# Copyright 2023 ISP RAS
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

# Install build dependencies.
WORKDIR /jazzer.js
RUN npm install strnum
ENV PATH=$PATH:/jazzer.js/fuzz/sydr

# Clone target from GitHub.
RUN git clone https://github.com/NaturalIntelligence/fast-xml-parser && \
    cd fast-xml-parser && git checkout 940a1421a9155cc2642725263fc7ccedbe914e35

# Copy build script and targets.
COPY fuzz.js fast-xml-parser/
RUN chmod +x fast-xml-parser/fuzz.js

# Prepare seed corpus and dict.
COPY xml.dict /
RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git /go-fuzz-corpus
RUN cp -r /go-fuzz-corpus/xml/corpus /corpus
