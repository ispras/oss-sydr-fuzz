# Copyright 2018 Google Inc.
# Modifications copyright (C) 2023 ISP RAS
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
RUN apt-get update && apt-get install -y autoconf make libtool zip
RUN git clone https://chromium.googlesource.com/webm/libwebp
RUN git clone https://chromium.googlesource.com/webm/libwebp-test-data
ADD https://storage.googleapis.com/downloads.webmproject.org/webp/testdata/fuzzer/fuzz_seed_corpus.zip /
RUN unzip fuzz_seed_corpus.zip -d libwebp-test-data/
RUN rm fuzz_seed_corpus.zip
COPY build.sh  /
COPY  main.c huffman_fuzzer.c vuln.patch /libwebp/
WORKDIR libwebp
# CVE-2023-4863
RUN git checkout 7ba44f80f3b94fc0138db159afea770ef06532a0
COPY huffman_fuzzer.c /libwebp/tests/fuzzer/
RUN git apply vuln.patch
RUN ../build.sh

RUN mkdir /corpus && cp -r /libwebp-test-data/*.webp /corpus/
