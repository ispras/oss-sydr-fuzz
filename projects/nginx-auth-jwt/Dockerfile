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

# Install build dependencies.
RUN apt-get update && apt-get install -y libssl-dev

RUN git clone --depth 1 https://github.com/google/fuzzing
RUN cp fuzzing/dictionaries/json.dict /
RUN rm -rf fuzzing

# Clone target from GitHub.
RUN git clone https://github.com/akheron/jansson.git
RUN git clone https://github.com/kjdev/nginx-auth-jwt.git

# Copy build script and fuzz targets.
COPY build.sh prepare_corpus.py jwt.patch ./
RUN mkdir /fuzz_targets
COPY jwt_parse.c jwt_claim.c jwks_parse.c /fuzz_targets/

# Build fuzz targets.
RUN ./build.sh

# Prepare corpus
RUN ./prepare_corpus.py /nginx-auth-jwt/t/data /corpus

WORKDIR /
