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

RUN git clone https://github.com/langchain-ai/langchain.git

WORKDIR /langchain

RUN git checkout 27aa4d38bf93f3eef7c46f65cc0d0ef3681137eb \
    && python3 -m pip install libs/langchain libs/community pypdf cryptography==3.1

WORKDIR /

COPY retriever.py process_json.py process_pdf.py /

# Prepare pdf corpus
RUN git clone https://github.com/mozilla/pdf.js pdf.js && \
    mkdir -p /pdf_corpus && \
    cp pdf.js/test/pdfs/*.pdf /pdf_corpus && \
    rm -rf pdf.js
ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/pdf.dict /pdf.dict

# Prepare json corpus
RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    mv go-fuzz-corpus/json/corpus /json_corpus && rm -rf go-fuzz-corpus
RUN git clone --depth 1 https://github.com/google/fuzzing && \
    cp fuzzing/dictionaries/json.dict /json.dict && rm -rf fuzzing
